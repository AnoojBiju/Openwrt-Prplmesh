###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

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
