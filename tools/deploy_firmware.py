#!/usr/bin/env python3

import time
import sys
import os
import subprocess
import difflib
import argparse
import shutil
from typing import List

from enum import Enum
from pathlib import Path

import pexpect
import pexpect.fdpexpect
import pexpect.pxssh
import serial
import re


class ShellType(Enum):
    """ ShellType enum contains 3 types of the possible shell on the device:

        UBOOT, PRPLWRT, RDKB
    """
    UBOOT = 1
    PRPLWRT = 2
    RDKB = 3


def check_serial_type(serial_name: str, baudrate: int, prompt_regexp: str) -> str:
    """ Checks type of the serial terminal.

    Parameters
    ----------
    serial_name: str
        Name of the serial device.

    baudrate: int, optional
        Serial baud rate.

    prompt_regexp: str
        Regular expression with shell prompt.

    Returns
    -------
    int
        Enum for rdkb, prplwrt or uboot shell otherwise raise exception.

    Raises
    -------
    ValueError
        If the connecting to the serial device failed.
    """

    serial_path = f"/dev/{serial_name}"
    if not os.path.exists(serial_path):
        raise ValueError(f"The serial device {serial_path} does not exist!\n"
                         + "Please make sure you have an appropriate udev rule for it.")
    UBOOT_PROMPT = "=>"
    OSTYPE_RE = r"NAME=[^\s]*"

    with serial.Serial(serial_path, baudrate) as ser:
        shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer, timeout=20)
        if not shell.isalive():
            raise ValueError("Unable to connect to the serial device!")

            shell.sendline("")
            shell.expect([UBOOT_PROMPT, pexpect.TIMEOUT])
            if shell.match is not pexpect.TIMEOUT:
                return ShellType.UBOOT

        shell.expect([prompt_regexp, pexpect.TIMEOUT])
        shell.sendline("")
        shell.sendline("cat /etc/os-release")

        os_name = ""

        # Read 25 lines from terminal for getting OS Type
        read_lines = 25

        while read_lines != 0:
            try:
                read_lines = read_lines - 1
                tmp = shell.readline()
                os_name = re.findall(OSTYPE_RE, tmp.decode("utf-8"))
                if os_name:
                    break
            except pexpect.TIMEOUT:
                continue

        for i in os_name:
            os_name = str(i)

        if re.findall(r"OpenWrt", os_name):
            return ShellType.PRPLWRT
        elif re.findall(r"RDK", os_name):
            return ShellType.RDKB
        else:
            raise ValueError("Unknown device type!")


def check_uboot_var(shell, variable: str, expectation: str):
    """ Check content of the UBoot variable.

    Parameters
    ----------
    shell : pexpect.fdpexpect.fdspawn
        Shell file descriptor.

    variable : str
        The number of seconds to wait between attempts.

    expectation: str
        Expected content of the variable.

    Raises
    -------
    ValueError
        If the getting content of the variable failed.
    """

    UBOOT_PROMPT = "=>"
    """ Standard UBoot prompt."""

    shell.sendline(f"printenv {variable}")
    shell.expect([expectation, pexpect.TIMEOUT])
    shell.expect([UBOOT_PROMPT, pexpect.TIMEOUT])
    if shell.match == pexpect.TIMEOUT:
        raise ValueError(f"Failed to get {variable} variable.")


def serial_cmd_err(shell, cmd_prompt: str, command: str):
    """ Execute command via serial port and check error code.

    Parameters
    ----------
    shell : int
        Shell file descriptor.

    cmd_prompt :
        Serial prompt.

    command : str
        Command which should be executed.

    Raises
    -------
    ValueError
        If command prompt not found or failed to execute command.
    """
    shell.sendline("")
    shell.expect([cmd_prompt, pexpect.TIMEOUT])
    if shell.match == pexpect.TIMEOUT:
        raise ValueError("Failed to get serial prompt!")

    shell.sendline(f"{command};echo err_code $?")
    shell.expect(["err_code 0", pexpect.TIMEOUT])
    if shell.match == pexpect.TIMEOUT:
        raise ValueError(f"Failed to execute {command}!")


class PrplwrtDevice:
    """Represents a prplWrt device.

    Offers methods to check if a device needs to be upgraded and to do the actual upgrade.

    It needs to have access to the artifacts of a build job to determine when an upgrade
    is needed (see `artifacts_dir`).
    """

    serial_prompt = "_pexpect_prompt_ "
    """For serial connections we will set this prompt to make it easier to "expect" it."""

    baudrate = 115200
    """The baudrate of the serial connection to the device."""

    initialization_time = 60
    """The time (in seconds) the device needs to initialize when it boots
    for the first time after flashing a new image."""

    def __init__(self, device: str, name: str, image: str, username: str = "root"):
        """

        Parameters
        -----------
        device: str
            The name of the platform (example: nec-wx3000hp).
        name: str
            The name of the device (it should ne reachable through ssh without a password).
        image: str
            The name of the image that can be used to upgrade the device.
        username: str, optional
            The username to use when connecting to the device over SSH.
        """
        self.device = device
        self.name = name
        self.image = image
        self.username = username

        self.rootdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
        self.artifacts_dir = os.path.join(self.rootdir, "build/{}".format(self.device))
        """The directory where artifacts are stored. It's expected to contain
        prplwrt-version, and the image file."""

    def set_prompt(self, pexp: pexpect):
        """Set the prompt to `serial_prompt` on a pexpect object."""
        pexp.sendline("export PS1='{}'".format(self.serial_prompt))

    def read_remote_version(self) -> List[str]:
        """Read prplwrt-version on a remote device

        Returns
        -------
        List[str]
            The content of the prplwrt-version file on the device as a list of strings.
        """
        version = None
        with pexpect.pxssh.pxssh(logfile=sys.stdout.buffer) as shell:
            shell.login(self.name, self.username)
            shell.sendline("cat /etc/prplwrt-version")
            shell.expect("cat /etc/prplwrt-version")
            shell.prompt()
            # remove the first (empty) line:
            version = shell.before.decode().splitlines()[1:]
        return version

    def read_artifacts_dir_version(self) -> List[str]:
        """Reads the local prplwrt-version.

        The version file is read from the artifacts (see `artifacts_dir`).

        Returns
        -------
        List[str]
            The content of the local prplwrt-version as a list of strings.
        """
        with open(os.path.join(self.artifacts_dir, "prplwrt-version")) as version_file:
            return version_file.read().splitlines()

    def needs_upgrade(self):
        """Check if a device needs to be updated

        The check is done by comparing prplwrt-version on the target
        with a local one (see `read_artifacts_dir_version).
        """
        artifacts_dir_version = self.read_artifacts_dir_version()
        remote_version = self.read_remote_version()
        diff = difflib.unified_diff(artifacts_dir_version, remote_version,
                                    fromfile='artifacts', tofile='device')
        diff_str = '\n'.join(diff)
        if diff_str:
            print(diff_str)
        return bool(diff_str)

    def reach(self, attempts: int = 5, wait: int = 5) -> bool:
        """Check if the device is reachable via SSH (and optionally try multiple times).

        Parameters
        ----------
        attempts: int, optional
            How many times we try before concluding that the device is unreachable.
        wait: int, optional
            The number of seconds to wait between attempts.

        Returns
        -------
        bool
            True if the device is reachable via SSH, false otherwise.
        """
        for _ in range(attempts):
            try:
                with pexpect.pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                                                  "UserKnownHostsFile": "/dev/null"}) as shell:
                    shell.login(self.name, self.username, login_timeout=5)
                    return True
            except (pexpect.pxssh.ExceptionPxssh, pexpect.exceptions.EOF):
                print("Waiting for the device to be reachable")
                time.sleep(wait)
        return False

    def sysupgrade(self):
        """Upgrade the device using sysupgrade."""
        raise NotImplementedError

    def upgrade_uboot(self):
        """Upgrade the device through uboot."""
        raise NotImplementedError


class Axepoint(PrplwrtDevice):
    """An axepoint or any similar device (e.g. NEC WX3000HP).

    At the moment, the device can only be updated through uboot using a tftp server.
    """

    tftp_dir = "/srv/tftp"
    """The root directory of the tftp server. The image will be copied there"""

    uboot_prompt = "GRX500 #"
    """The u-boot prompt on the target."""

    def _update_fullimage(self, shell: pexpect.fdpexpect.fdspawn):
        """Stop the u-boot sequence, set env variables and run update_fullimage

        Parameters
        ----------
        shell: pexpect.fdpexpect.fdspawn
            The serial console to send commands to.
        """
        shell.expect(["Hit any key to stop autoboot:",
                      pexpect.EOF, pexpect.TIMEOUT], timeout=120)
        # stop autoboot:
        shell.sendline("")
        shell.expect(self.uboot_prompt)
        # set the image name and save it:
        shell.sendline("setenv fullimage {} ; saveenv".format(self.image))
        shell.expect(self.uboot_prompt)
        # do the actual upgrade:
        shell.sendline("run update_fullimage")
        shell.expect("Creating dynamic volume .* of size", timeout=120)
        shell.expect(r"(?i)Writing to nand\.\.\. (ok|done)", timeout=60)
        shell.expect(self.uboot_prompt, timeout=600)

    def upgrade_uboot(self):
        """Upgrade the device through u-boot.

        It requires a running tftp server listenning on the IP the
        target device will expect (see `ipaddr` in the uboot environment).
        """
        serial_path = "/dev/{}".format(self.name)
        if not os.path.exists(serial_path):
            raise ValueError("The serial device {} does not exist!\n".format(serial_path)
                             + "Please make sure you have an appropriate udev rule for it.")
        print("Copying image '{}' to '{}'".format(self.image, self.tftp_dir))
        shutil.copy(os.path.join(self.artifacts_dir, self.image), self.tftp_dir)
        print("Image copied to {}.".format(self.tftp_dir))
        with serial.Serial(serial_path, self.baudrate) as ser:
            print("Connecting to serial")
            shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer)
            if not shell.isalive():
                raise ValueError("Unable to connect to the serial device!")
            print("Connected")
            # The console might not be active yet:
            shell.sendline("")
            # make the shell prompt appear:
            self.set_prompt(shell)
            shell.expect(self.serial_prompt)
            # kill any instance of the init script, if the current
            # firmware doesn't have working wireless interfaces it
            # will prevent it from rebooting:
            shell.sendline("pgrep -f 'S99prplmesh boot' | xargs kill")
            # remove overlay and reboot
            shell.sendline("rm -rf /overlay/upper/usr /overlay/upper/opt "
                           "    /overlay/upper/etc/config/wireless "
                           "    /overlay/upper/lib/netifd "
                           "    /overlay/upper/etc/uci-defaults/15_wireless-generate-macaddr")
            shell.sendline("reboot -f")
            try:
                self._update_fullimage(shell)
            except pexpect.exceptions.TIMEOUT:
                print("The upgrade timed out, trying one more time after a reboot.")
                # Interrupt any running command:
                shell.send('\003')
                shell.sendline("reset")
                try:
                    self._update_fullimage(shell)
                except pexpect.exceptions.TIMEOUT:
                    print("The upgrade failed again, aborting.")
            print("The upgrade is done, rebooting.")
            # reboot:
            shell.sendline("reset")
            shell.expect("Please press Enter to activate this console", timeout=180)
            # activate the console:
            shell.sendline("")
            self.set_prompt(shell)
            shell.expect(self.serial_prompt)
            shell.sendline("exit")
        if not self.reach(attempts=10):
            raise ValueError("The device was not reachable after the upgrade!")
        # Wait at least for the CAC timer:
        time.sleep(self.initialization_time)


class Generic(PrplwrtDevice):
    """A generic PrplwrtDevice.

    Since upgrading through uboot is generally target-specific, it
    only offers the sysupgrade option.
    """

    def sysupgrade(self):
        serial_path = "/dev/{}".format(self.name)
        if not os.path.exists(serial_path):
            raise ValueError("The serial device {} does not exist!\n".format(serial_path)
                             + "Please make sure you have an appropriate udev rule for it.")
        print("Copying image '{}' to the target".format(self.image))
        try:
            subprocess.check_output(["scp",
                                     "{}/{}".format(self.artifacts_dir, self.image),
                                     "{}:/tmp/{}".format(self.name, self.image)])
        except subprocess.CalledProcessError as exc:
            print("Failed to copy the image to the target:\n{}".format(exc.output))
            raise exc
        with serial.Serial(serial_path, self.baudrate) as ser:
            print("Connecting to serial")
            shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer)
            if not shell.isalive():
                raise ValueError("Unable to connect to the serial device!")
            print("Connected")
            # The console might not be active yet:
            shell.sendline("")
            # make the shell prompt appear:
            self.set_prompt(shell)
            shell.expect(self.serial_prompt)
            # Turn off the wifi to make sure it doesn't prevent the upgrade:
            shell.sendline("wifi down")
            # Do the upgrade
            shell.sendline("sysupgrade -v /tmp/{}".format(self.image))
            # first give it 30 seconds, and fail early if the upgrade didn't start:
            shell.expect(r"Performing system upgrade\.\.\.", timeout=30)
            # now give it more time to apply the upgrade and reboot:
            shell.expect(r"Rebooting system\.\.\.", timeout=300)
            shell.expect("Please press Enter to activate this console", timeout=180)
            # activate the console:
            shell.sendline("")
            self.set_prompt(shell)
            shell.expect(self.serial_prompt)
            shell.sendline("exit")
        if not self.reach(attempts=10):
            raise ValueError("The device was not reachable after the upgrade!")
        time.sleep(self.initialization_time)


class TurrisRdkb(PrplwrtDevice):
    """Represents a RDKB device.

    Offers methods to check if a device needs to be upgraded and to do the actual upgrade.

    It needs to have access to the artifacts of a build job to determine when an upgrade
    is needed (see `artifacts_dir`).
    """

    BAUDRATE = 115200
    """The baudrate of the serial connection to the device."""

    initialization_time = 60
    """The time (in seconds) the device needs to initialize when it boots
    for the first time after flashing a new image."""

    TURRIS_DTB = "armada-385-turris-omnia.dtb"
    """ Device Tree Blob (Flat Device Tree) for Turris Omnia.
    The DTB is a database that represents the hardware components on a given board. """

    KERNEL_PARTITION = "mmcblk0p3"
    """ eMMC partiotion used for RDKB kernel (zImage) and DTB file."""

    ROOTFS_PARTITION = "mmcblk0p5"
    """ eMMC partition used for RDKB rootfs."""

    PROMPT_RE = r'root@[^\s]+:[^\s]+# '
    """ Regular expression for root prompt."""

    UBOOT_PROMPT = "=>"
    """ Standard UBoot prompt."""

    def __init__(self, device: str, name: str, rdkbfs: str, kernel: str, username: str = "root"):
        """

        Parameters
        -----------
        device: str
            The name of the platform (example: turris-omnia).
        name: str
            The name of the device (it should be reachable through ssh without a password).
        rdkbfs: str
            The name of the rdkbfs tarball that can be used to upgrade the device.
        kernel: str
            The name of the kernel binary that can be used to upgrade kernel on device.
        username: str, optional
            The username to use when connecting to the device over SSH.
        """
        self.device = device
        self.name = name
        self.rdkbfs = rdkbfs
        self.username = username
        self.kernel = kernel

        self.rootdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
        self.artifacts_dir = os.path.join(self.rootdir, "build/{}".format(self.device))
        """The directory where artifacts are stored. It's expected to contain the
        image, kernel, dtb files."""

    def reset_board(self, serial_type: ShellType):
        """Reset board.

        Parameters
        -----------
        serial_type: ShellType
            Type of the serial connection as enum ShellType(uboot, rdkb, prplwrt)
        """
        serial_path = f"/dev/{self.name}"
        if not os.path.exists(serial_path):
            raise ValueError(f"The serial device {serial_path} does not exist!\n"
                             + "Please make sure you have an appropriate udev rule for it.")

        with serial.Serial(serial_path, self.BAUDRATE) as ser:
            print("Reset board.")

            shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer, timeout=20)
            if not shell.isalive():
                raise ValueError("Unable to connect to the serial device!")

            if serial_type == ShellType.UBOOT:
                shell.sendline("reset")
            elif serial_type == ShellType.PRPLWRT or \
                    serial_type == ShellType.RDKB:
                shell.sendline("reboot")

    def check_images_on_board(self):
        """Check images on the Turris Omnia.

            If images was not copied return False, otherwise True.
        """

        serial_path = f"/dev/{self.name}"
        if not os.path.exists(serial_path):
            raise ValueError(f"The serial device {serial_path} does not exist!\n"
                             + "Please make sure you have an appropriate udev rule for it.")

        with serial.Serial(serial_path, self.BAUDRATE) as ser:
            shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer, timeout=30)
            if not shell.isalive():
                raise ValueError("Unable to connect to the serial device!")

            def find_file(file_name: str):
                shell.sendline("")
                shell.expect(self.PROMPT_RE)
                shell.sendline(f"find /tmp -maxdepth 1 -name {file_name}")
                shell.expect([f"/tmp/{file_name}", pexpect.TIMEOUT])
                if shell.match == pexpect.TIMEOUT:
                    raise ValueError(f"File {file_name} not found.")

            shell.sendline("")
            find_file(self.rdkbfs)
            find_file(self.kernel)
            find_file(self.TURRIS_DTB)

    def load_rdkb_firmware(self):
        """Copy RDKB rootfs and kernel to the Turris Omnia.
        """

        print(f"Copying '{self.rdkbfs}'\n'{self.kernel}'\n'{self.TURRIS_DTB}'\n to the target")
        try:
            subprocess.check_output(["scp", "-o StrictHostKeyChecking=no",
                                     f"{self.artifacts_dir}/{self.rdkbfs}",
                                     f"{self.username}@{self.name}:/tmp/{self.rdkbfs}"])
            subprocess.check_output(["scp", "-o StrictHostKeyChecking=no",
                                     f"{self.artifacts_dir}/{self.kernel}",
                                     f"{self.username}@{self.name}:/tmp/{self.kernel}"])
            subprocess.check_output(["scp", "-o StrictHostKeyChecking=no",
                                     f"{self.artifacts_dir}/{self.TURRIS_DTB}",
                                     f"{self.username}@{self.name}:/tmp/{self.TURRIS_DTB}"])
        except subprocess.CalledProcessError as exc:
            print(f"Failed to copy the image to the target:\n{exc.output}")
            raise exc

    def burn_rdkb_on_board(self):
        """Burn RDKB image on Turris Omnia.
        """

        self.check_images_on_board()

        serial_path = f"/dev/{self.name}"
        if not os.path.exists(serial_path):
            raise ValueError(f"The serial device {serial_path} does not exist!\n"
                             + "Please make sure you have an appropriate udev rule for it.")

        with serial.Serial(serial_path, self.BAUDRATE) as ser:
            shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer, timeout=40)
            if not shell.isalive():
                raise ValueError("Unable to connect to the serial device.")

            def mount_mmc(partition: str):
                serial_cmd_err(shell, self.PROMPT_RE, f"mount /dev/{partition} /mnt")
                shell.sendline("mount")
                shell.expect(f"/dev/{partition} on /mnt")

            def umount_mmc():
                serial_cmd_err(shell, self.PROMPT_RE, "umount /mnt")
                shell.sendline("du -sh /mnt")
                shell.expect("0")

            def copy_to_mmc(src: str, dst: str):
                try:
                    serial_cmd_err(shell, self.PROMPT_RE, f"cp -v {src} {dst}")
                except ValueError:
                    umount_mmc()
                    raise

            def check_partition(partition: str):
                shell.sendline("")
                shell.expect(self.PROMPT_RE)
                shell.sendline(f"find /dev/ -maxdepth 1 -name {partition}")
                shell.expect([f"/dev/{partition}", pexpect.TIMEOUT])
                if shell.match == pexpect.TIMEOUT:
                    raise ValueError(
                        f"Partition {partition} not found, need to create it.")

            shell.sendline("")
            print("Start to burn RDKB on Turris Omnia")

            check_partition(self.KERNEL_PARTITION)
            check_partition(self.ROOTFS_PARTITION)

            shell.sendline("")

            mount_mmc(self.KERNEL_PARTITION)

            print("Install kernel.")
            copy_to_mmc(f"/tmp/{self.kernel}", "/mnt/zImage")

            shell.sendline("")

            print("Install Device Tree Blob")
            copy_to_mmc(f"/tmp/{self.TURRIS_DTB}", f"/mnt/{self.TURRIS_DTB}")

            shell.sendline("")

            umount_mmc()

            shell.sendline("")

            print("Install RDKB rootfs.")
            mount_mmc(self.ROOTFS_PARTITION)

            shell.sendline("")

            serial_cmd_err(shell, self.PROMPT_RE, "rm -rf /mnt/*")
            shell.sendline("du -sh /mnt")
            shell.expect("0")

            serial_cmd_err(shell, self.PROMPT_RE, f"tar -xzf /tmp/{self.rdkbfs} -C /mnt/")

            shell.sendline("")

            umount_mmc()

    def load_rdkb(self):
        """ Launch RDKB on Turris Omnia.

            Raises
            -----------
            ValueError
                If serial does not exist or unable to connect.
        """

        self.reset_board(check_serial_type(self.name, self.BAUDRATE, self.PROMPT_RE))

        common_bridge_ip = "192.168.200.140"
        common_net_mask = "24"
        rdkb_bridge = "lan4.200"

        serial_path = f"/dev/{self.name}"
        if not os.path.exists(serial_path):
            raise ValueError(f"The serial device {serial_path} does not exist!\n"
                             + "Please make sure you have an appropriate udev rule for it.")

        with serial.Serial(serial_path, self.BAUDRATE) as ser:
            shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer, timeout=30)
            if not shell.isalive():
                raise ValueError("Unable to connect to the serial device.")

            shell.expect("Hit any key to stop autoboot")
            shell.sendline("")
            shell.expect(self.UBOOT_PROMPT)

            check_uboot_var(shell, "yocto_bootargs", "yocto_bootargs=earlyprintk")
            check_uboot_var(shell, "mmcboot", "mmcboot=run")
            check_uboot_var(shell, "yocto_mmcload", "yocto_mmcload=setenv")

            shell.sendline("run mmcboot")
            shell.expect(["TurrisOmnia-GW login", pexpect.TIMEOUT])

            # Add vlan. Will be used for SSH connection
            shell.sendline(f"ip link add link lan4 name {rdkb_bridge} type vlan id 200")
            shell.sendline(f"RES=$?")
            shell.sendline(f"echo PRPL=$RES")
            shell.expect(f"PRPL=0")
            shell.sendline(f"ip a a {common_bridge_ip}/{common_net_mask} dev {rdkb_bridge}")
            shell.expect([f"ip a a {common_bridge_ip}/{common_net_mask} dev {rdkb_bridge}"])
            # Remove firewall rule which blocks SSH connection
            shell.sendline("iptables -D INPUT -i lan0 -p tcp -m tcp --dport 22 -j DROP")
            shell.expect("iptables -D INPUT -i lan0 -p tcp -m tcp --dport 22 -j DROP")

    def sysupgrade(self):
        """Upgrade RDKB image on Turris Omnia and launch it.
        """

        self.load_rdkb_firmware()

        self.burn_rdkb_on_board()

        self.load_rdkb()

    def read_rdkb_rootfs_version(self) -> str:
        """ Read new image version.

            Returns
            -----------
                String with image build date otherwise empty string.
        """

        image_name_re = r"rdkb[^\s]+[\d*]+[^\s]\.rootfs\.tar\.gz"
        """ Find correct RDKB rootfs file."""

        image_date_re = r"0*[1-9]\d{4,}"
        """ Retrieve RDKB rootfs build date."""

        image = ""
        for artifact in Path(self.artifacts_dir).iterdir():
            image = re.findall(image_name_re, str(artifact))
            if image:
                break

        date_list = re.findall(image_date_re, str(image))

        date = ""
        for i in date_list:
            date = str(i)

        return date

    def read_remote_rdkb_version(self) -> str:
        """ Read current RDKB rootfs version.

            Returns
            -----------
            str
                RDKB rootfs version.

            Raises
            -----------
            ValueError
                If version of rootfs not found.
        """

        RDKB_VERSION_PATH = "/mnt/etc/version"
        IMAGE_DATE_RE = r"0*[1-9]\d{4,}"
        """ Retrieve RDKB rootfs build date."""

        with pexpect.pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                                          "UserKnownHostsFile": "/dev/null"}) as shell:
            shell.login(self.name, self.username)

            shell.sendline(f"mount /dev/{self.ROOTFS_PARTITION} /mnt")
            shell.prompt()
            shell.sendline("mount")
            shell.expect(f"/dev/{self.ROOTFS_PARTITION} on /mnt")

            shell.sendline(f"cat {RDKB_VERSION_PATH}")
            shell.expect([f"cat {RDKB_VERSION_PATH}", pexpect.TIMEOUT])
            shell.prompt()
            version = re.findall(IMAGE_DATE_RE, shell.before.decode())
            if not version:
                # We need to add dummy version for handling case when we flash new board or board
                # where RDKB rootfs was brocken and version file does not exist.
                version = "1"

            shell.sendline("umount /mnt")
            shell.expect("umount /mnt")
            shell.prompt()

            for i in version:
                version = str(i)

            return version

    def needs_upgrade(self) -> bool:
        """ Check if we need to upgrade the board or not.

            Returns
            -----------
            bool
                True if upgrade required otherwise False.

            Raises
            -----------
            ValueError
                If failed to get serial connection or prplwrt is not ready for use
        """

        def is_prplwrt_ready() -> bool:
            """ Checks if prplwrt propmpt ready to use after reboot"""

            serial_path = f"/dev/{self.name}"
            if not os.path.exists(serial_path):
                raise ValueError(f"The serial device {serial_path} does not exist!\n"
                                 + "Please make sure you have an appropriate udev rule for it.")

            with serial.Serial(serial_path, self.BAUDRATE) as ser:
                shell = pexpect.fdpexpect.fdspawn(ser, logfile=sys.stdout.buffer, timeout=60)
                if not shell.isalive():
                    raise ValueError("Unable to connect to the serial device.")

                shell.expect(["Please press Enter to activate this console.", pexpect.TIMEOUT])
                if shell.match == pexpect.TIMEOUT:
                    return False

                shell.sendline("")
            return True

        serial_type = check_serial_type(self.name, self.BAUDRATE, self.PROMPT_RE)
        if serial_type == ShellType.UBOOT:
            self.reset_board(serial_type)
            if not is_prplwrt_ready():
                raise ValueError("Failed to get ready prplwrt serial.")

        current_version = int(self.read_remote_rdkb_version())
        new_version = int(self.read_rdkb_rootfs_version())

        print(f"Current RDKB version is: {current_version} \nNew RDKB version is: {new_version}")

        will_upgrade = new_version > current_version
        if will_upgrade and serial_type == ShellType.RDKB:
            self.reset_board(check_serial_type(self.name, self.BAUDRATE, self.PROMPT_RE))
            if not is_prplwrt_ready():
                raise ValueError("Failed to get ready prplwrt serial.")

        return will_upgrade


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description="""Update a prplWrt device, either through u-boot
                                     or using sysupgrade, depending on the target device.""")
    parser.add_argument('-d', '--device',
                        help="""Device to upgrade. Currently supported targets are: nec-wx3000hp
                        glinet-b1300 turris-omnia axepoint""", required=True)
    parser.add_argument(
        '-t',
        '--target-name',
        help="Name of the target to upgrade (make sure it's reachable through ssh).", required=True)

    parser.add_argument(
        '-i',
        '--image',
        help="Name of the image to use for the upgrade (should exist in the artifacts folder).",
        required=True)

    parser.add_argument(
        '-o',
        '--os-type',
        help="Type of the operating system: rdkb or prplWrt.",
        default="prplwrt")

    parser.add_argument(
        '-k',
        '--kernel',
        help="Kernel for RDKB type of image.")

    args = parser.parse_args()

    if args.device in ["axepoint", "nec-wx3000hp"]:
        dev = Axepoint(args.device, args.target_name, args.image)
    elif args.os_type == "rdkb":
        dev = TurrisRdkb(args.device, args.target_name, args.image, args.kernel)
    else:
        dev = Generic(args.device, args.target_name, args.image)

    print("Checking if the device is reachable over ssh")
    if not dev.reach():
        raise ValueError("The device {} is not reachable over ssh! check your ssh configuration."
                         .format(dev.name))
    print("Checking if the device needs to be upgraded")
    if dev.needs_upgrade():
        print("The device {} will be upgraded".format(dev.name))
        try:
            dev.sysupgrade()
        except NotImplementedError:
            dev.upgrade_uboot()
        print("Checking if the device was properly updated")
        if dev.needs_upgrade():
            print("Something went wrong with the update!")
            sys.exit(1)
        print("Done")
    else:
        print("The device is already using the same version, no upgrade will be done.")


if __name__ == '__main__':
    main()
