###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# Standard library
import os
import shutil
import time

# Third party
import pexpect
import pexpect.fdpexpect
import pexpect.pxssh
from device.prplos import PrplOSDevice
from device.serial import SerialDevice


class Axepoint(PrplOSDevice):
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
        with SerialDevice(self.baudrate, self.name, self.serial_prompt) as ser:
            shell = ser.shell
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
            shell.expect(self.serial_prompt)
            shell.sendline("exit")
        if not self.reach(attempts=10):
            raise ValueError("The device was not reachable after the upgrade!")
        # Wait at least for the CAC timer:
        time.sleep(self.initialization_time)
