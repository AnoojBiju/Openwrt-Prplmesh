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


class Haze(GenericPrplOS):
    """A WNC Haze running prplOS.

    A tftp server must be running to serve images, and both 'serverip'
    and 'ipaddr' should already be set in the bootloader.
    """

    bootloader_prompt = r"IPQ807x# "
    """The u-boot prompt on the target."""

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
        time.sleep(10)

        shell.sendline(f"tftpboot 0x44000000 {self.image}")
        shell.sendline("")
        shell.expect("Loading: ")
        shell.expect("done")
        shell.expect(self.bootloader_prompt)

        shell.sendline("setenv untar_addr_kernel; setenv untar_addr_root")
        shell.expect(self.bootloader_prompt)

        shell.sendline("untar 0x$fileaddr 0x$filesize kernel root")
        shell.expect("filename: sysupgrade-prpl_haze/CONTROL")
        shell.expect("filename: sysupgrade-prpl_haze/kernel")
        shell.expect("filename: sysupgrade-prpl_haze/root")
        shell.expect(self.bootloader_prompt)

        shell.sendline("if test -n $untar_addr_kernel; then flash '0:HLOS' 0x$untar_addr_kernel 0x$untar_size_kernel; else echo 'kernel not found'; fi") # noqa E501
        shell.expect("blocks erased: OK", timeout=10)
        shell.expect("blocks written: OK", timeout=10)
        shell.expect(self.bootloader_prompt)

        shell.sendline("if test -n $untar_addr_root; then flash 'rootfs' 0x$untar_addr_root 0x$untar_size_root; else echo 'rootfs not found'; fi") # noqa E501
        shell.expect("blocks erased: OK", timeout=10)
        shell.expect("blocks written: OK", timeout=10)
        shell.expect(self.bootloader_prompt)
