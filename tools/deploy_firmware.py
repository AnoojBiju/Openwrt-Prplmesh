#!/usr/bin/env python3
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020-2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# Standard library
import argparse
import time
import sys
from pathlib import Path

# Third party
from device.configuration import configure_device
from device.get_device import device_from_name


def replace_build_dir(build_directory):
    reversed_dir = build_directory[::-1]
    replaced_dir = reversed_dir.replace("/build/"[::-1], "/buildWHM/"[::-1], 1)
    return replaced_dir[::-1]


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description="""Update a prplOS device, either through u-boot
                                     or using sysupgrade, depending on the target device.""")
    parser.add_argument('-d', '--device',
                        help="""Device to upgrade. Currently supported targets are: nec-wx3000hp
                        glinet-b1300 turris-omnia axepoint haze urx_osp""", required=True)
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

    parser.add_argument(
        '-w',
        '--whm',
        action='store_true',
        help="Flash using the WHM build")

    parser.add_argument(
        '-c',
        '--configuration',
        help="The path to an optional configuration file.", required=False)

    args = parser.parse_args()

    dev = device_from_name(args.device, args.target_name, args.image)

    # Replaces the last occurence of /build/ with /buildWHM/ in the devices's artifacts dir
    if args.whm:
        dev.artifacts_dir = replace_build_dir(dev.artifacts_dir)

    def do_upgrade(dev):
        try:
            dev.upgrade_bootloader()
        except NotImplementedError:
            dev.sysupgrade()

    needs_upgrade = False
    if args.full:
        print("--full was provided, the device {} will be upgraded".format(dev.name))
        needs_upgrade = True
    else:
        print("Checking if the device needs to be upgraded")
        needs_upgrade = False
        try:
            needs_upgrade = dev.needs_upgrade()
        except Exception:  # pylint: disable=broad-except
            print("Couldn't determine if the device needs to be ugpgraded. Upgrading anyway.")
            needs_upgrade = True
    if needs_upgrade:
        print("The device {} will be upgraded".format(dev.name))
        do_upgrade(dev)
        # do_upgrade will wait for the specified initialisation time
    else:
        print("The device is already using the same version, no upgrade will be done.")

    # Apply the configuration if there is one:
    if args.configuration:
        print("A configuration file was provided, it will be applied.")
        configure_device(dev, Path(args.configuration))
        print("Waiting for the device to initialize.")
        time.sleep(dev.configuration_initialization_time)

    if needs_upgrade and dev.needs_reboot_new_mac:
        print("Rebooting device to apply correct MACs on the interfaces (workaround)")
        dev.reboot_prplos()
        time.sleep(dev.reboot_time)

    print("Checking if the device is reachable.")
    if not dev.reach(attempts=10):
        raise ValueError("The device was not reachable after the upgrade!")

    # If the device had to be upgraded, check if the upgrade was successful:
    if needs_upgrade:
        print("Checking if the device was properly updated")
        if dev.needs_upgrade():
            print("Something went wrong with the update!")
            sys.exit(1)
    print("Done")


if __name__ == '__main__':
    main()
