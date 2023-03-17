###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
"""This module facilitates capturing logs from a device over serial."""

# Standard library
import os
import time
from collections import namedtuple
from datetime import datetime

# Third party
import pexpect
from device.generic import GenericDevice
from device.serial import SerialDevice
from device.utils import ShellType

LogCommand = namedtuple("LogCommand", "cmd, filename")

LOG_COMMANDS = \
    [
        LogCommand("cat /etc/config/network", "config-network.txt"),
        LogCommand("getDebugInformation --all -o -", "debug-information.txt"),
        LogCommand('find /etc/config/tr181-bridging/ -type f -print -exec cat {} \';\'',
                   "config-tr181-bridging.txt"),
        LogCommand('find /etc/amx/tr181-bridging/ -type f -print -exec cat {} \';\'',
                   "amx-tr181-bridging.txt"),
    ]


def capture_logs(device: GenericDevice, path: str):
    """Capture logs from a device over a serial line.

    Commands from LOG_COMMANDS are executed, and the results are saved
    in individual files (one file per command).

    It is assumed that the device is accessible over serial at
    /dev/device_name.
    Note that a udev rule can be used to create a symlink pointing to
    the right serial device.

    The logs to capture are defined statically in this file.

    Parameters
    ----------
    device
        The device to configure.
    path
        The path to save the log files to. If it doesn't exist, it
        will be created.
    """

    print("Checking that the device is booted into an OS.")
    if device.check_serial_type is ShellType.UBOOT:
        raise ValueError("The device is currently in bootloader, logs \
        cannot be captured.")
    print(f"Capturing logs from device {device.name}.")
    os.makedirs(path, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"{path}/all-console-{timestamp}.txt", "wb") as logfile:
        with SerialDevice(device.baudrate, device.name, device.serial_prompt,
                          expect_prompt_on_connect=False, logfile=logfile) as shell:
            shell.sendline("")
            time.sleep(1)
            # Interrupt any running command:
            shell.send("\003")
            shell.expect(device.serial_prompt)
            # There might have been two prompts, if no command had to be interrupted:
            shell.expect([device.serial_prompt, pexpect.TIMEOUT])
            for log in LOG_COMMANDS:
                shell.sendline(log.cmd)
                shell.expect(log.cmd)
                shell.expect(device.serial_prompt, timeout=180)
                cmd_output = shell.before.decode("utf-8")
                with open(f"{path}/{log.filename}", "w", encoding="utf-8") as output_file:
                    output_file.writelines(cmd_output)
    print("Done")
