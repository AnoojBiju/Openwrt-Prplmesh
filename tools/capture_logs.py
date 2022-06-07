#!/usr/bin/env python3
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

"""This script can be used to get logs from a device over a serial
connection.

It is assumed that the serial device is accessible at
/dev/<target-name> (use a udev rule if needed).

"""

# Standard library
import argparse
import sys

# Third party
from device.get_device import device_from_name
from device.logs import capture_logs


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description="""Get logs from a device over serial.""")
    parser.add_argument('-d', '--device',
                        help="""Device to configure. For a list of the supported devices, see the
                        get_device module.""", required=True)
    parser.add_argument(
        '-t',
        '--target-name',
        help="Name of the target.", required=True)
    parser.add_argument(
        '-o',
        '--output',
        help="The output directory for the logs (defaults to the current directory).", default=".")

    args = parser.parse_args()

    dev = device_from_name(args.device, args.target_name)
    capture_logs(dev, args.output)


if __name__ == '__main__':
    main()
