###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# Standard library
import re
from enum import Enum

# Third party
import pexpect
import pexpect.fdpexpect
import pexpect.pxssh
from device.serial import SerialDevice


class ShellType(Enum):
    """ ShellType enum contains 3 types of the possible shell on the device:

        UBOOT, PRPLOS, RDKB
    """
    UBOOT = 1
    PRPLOS = 2
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
        Enum for rdkb, prplOS or uboot shell otherwise raise exception.

    Raises
    -------
    ValueError
        If the connecting to the serial device failed.
    """

    UBOOT_PROMPT = "=>"
    OSTYPE_RE = r"NAME=[^\s]*"

    with SerialDevice(baudrate, serial_name, prompt_regexp,
                      expect_prompt_on_connect=False) as ser:
        shell = ser.shell
        shell.sendline("")
        shell.expect([UBOOT_PROMPT, pexpect.TIMEOUT])
        if shell.match is not pexpect.TIMEOUT:
            return ShellType.UBOOT

        # Silence kernel messages:
        shell.sendline("sysctl -w kernel.printk='0 4 1 7'")
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
            return ShellType.PRPLOS
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
    # Standard UBoot prompt.

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
