###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# Standard library
import time

# Third party
import pexpect
import pexpect.fdpexpect
import pexpect.pxssh
from device.prplos import GenericPrplOS


class URXOSP(GenericPrplOS):
    """An MXL Open Service Platform URX device running prplOS.

    A tftp server must be running to serve images, and both 'serverip'
    and 'ipaddr' should already be set in the bootloader.
    """

    initialization_time = 280
    """The time (in seconds) the device needs to initialize when it boots
    for the first time after flashing a new image."""

    bootloader_prompt = r"Lightning # "
    """The u-boot prompt on the target."""

    bootloader_reboot_command = "run bootcmd"
    """The command to reboot the device in u-boot"""

    def upgrade_from_u_boot(self, shell: pexpect.fdpexpect.fdspawn):
        """Upgrade from u-boot and remove the overlay.

        Parameters
        ----------
        shell: pexpect.fdpexpect.fdspawn
            The serial console to send commands to.
            It's assumed that the console is already stopped in u-boot.
        """
        shell.sendline("")
        shell.expect(self.bootloader_prompt)
        # Give the ethernet interfaces some time to initialize:
        time.sleep(5)

        # Changes the default image name to upgrade
        # shell.sendline(f"setenv fullimage {self.image}")
        # shell.sendline("")
        # shell.sendline("saveenv")
        # shell.expect("OK")

        shell.sendline("run update_fullimage")
        shell.expect("done", timeout=30)
        # Image transfer successful
        shell.expect("Found device tree image", timeout=15)
        shell.expect("Saving Environment to MMC", timeout=15)
        shell.expect("OK", timeout=15)
        # Image written to MMC
        shell.sendline("")
        shell.expect(self.bootloader_prompt)

        time.sleep(10)
        shell.sendline(
            "mmc erase ${overlay_container_a_block_start} ${overlay_container_a_block_size}")
        shell.expect("blocks erased: OK", timeout=15)
        time.sleep(5)
        shell.sendline(
            "mmc erase ${overlay_container_a_block_start} ${overlay_container_a_block_size}")
        shell.expect("blocks erased: OK", timeout=15)
        shell.expect(self.bootloader_prompt)
