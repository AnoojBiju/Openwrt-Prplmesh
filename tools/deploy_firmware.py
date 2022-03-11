#!/usr/bin/env python3
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020-2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# Standard library
import argparse
import sys

# Third party
from device.get_device import device_from_name


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description="""Update a prplOS device, either through u-boot
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
        '-f',
        '--full',
        action='store_true',
        help="Always flash the full image (even if it's not required).")

    args = parser.parse_args()

    dev = device_from_name(args.device, args.target_name, args.image)

    def do_upgrade(dev):
        try:
            dev.sysupgrade()
        except NotImplementedError:
            dev.upgrade_bootloader()
        print("Checking if the device was properly updated")
        if dev.needs_upgrade():
            print("Something went wrong with the update!")
            sys.exit(1)
        print("Done")

    if args.full:
        print("--full was provided, the device {} will be upgraded".format(dev.name))
        do_upgrade(dev)
    else:
        print("Checking if the device needs to be upgraded")
        if dev.needs_upgrade():
            print("The device {} will be upgraded".format(dev.name))
            do_upgrade(dev)
        else:
            print("The device is already using the same version, no upgrade will be done.")


if __name__ == '__main__':
    main()
