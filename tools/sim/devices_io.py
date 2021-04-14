###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

"""Parsing and dumping of a Multi-AP network.

This module contains functions to parse a network from a string, and to dump a network to a string.

The format is documented in example.network.
"""

from devices import Metric, Network
import re


class NetworkParseError(Exception):
    """Exception raised when attempting to parse a string with invalid format.

    Parameters
    ----------
    cause: str
        Explanation of what is wrong.
    line: str
        The line that caused the parse error.
    lineno: int
        The line number on which the parse error occurred.
    """
    def __init__(self, cause: str, line: str, lineno: int):
        self.cause = cause
        self.line = line
        self.lineno = lineno
        super().__init__(f"line {lineno}: {cause}\n\t{line}")


def parse_network(text: str) -> Network:
    """Parse a network from a string.

    Refer to example.network for the format of the string.

    Parameters
    ----------
    text: str
        The string to parse.

    Returns
    -------
    Network
        The parsed Network with devices and links.

    Raises
    ------
    NetworkParseError
        When a parse error occurs.
    """
    network = Network()

    # There's always a gateway
    network.add_device()

    # There is no switch attribute in Device, so keep a list of switches instead.
    switches = []

    for lineno, line in enumerate(text.split('\n')):
        # Remove comments.
        line = line.split('#', 1)[0]
        # Remove initial/final whitespace
        line = line.strip()

        if not line:
            continue

        device = network.add_device()

        fields = re.split(r'\s+', line)
        devicetype = fields[0]
        # We only look at the first letter, and only check for S
        is_switch = devicetype.startswith('S')
        if is_switch:
            switches.append(device)

        for idx, linkfield in enumerate(fields[1:]):
            if idx >= len(network.devices) - 1:
                raise NetworkParseError("More link fields than devices", line, lineno)
            if linkfield == "-":
                continue

            other = network.devices[idx]

            for linkspec in linkfield.split(";"):
                match = re.match(r'([0-9.]+)([A-Z]*)', linkspec)
                if not match:
                    raise NetworkParseError(f"Invalid link spec {linkspec}", line, lineno)
                metric, properties = match.groups()

                # For now, there is no distinction between wired and wireless links, and no AP/STA
                # role, so ignore the properties.
                device.add_link(other, Metric(float(metric)))

    return network


def dump_network(network: Network) -> str:
    """Dump a network into a string.

    Refer to example.network for the format of the string. The returned string always ends with a
    newline.

    Parameters
    ----------
    network: Network
        The network to dump.

    Returns
    -------
    str
        The string representation of the network.
    """
    s = "# Network dump\n"

    # Gateway is not represented. If there are no devices at all, just return an empty file anyway -
    # this is not an exact representation of the network, but that's an uninteresting corner case.
    if len(network.devices) <= 1:
        return s

    # For nicer formatting, we first collect all linkspecs and calculate column widths.
    column_widths = [3] * (len(network.devices) - 1)
    all_linkspecs = []  # List of lists of linkspecs
    for device in network.devices[1:]:
        device_linkspecs = []
        for other_idx, other in enumerate(network.devices[:device.idx]):
            links = device.links[other]
            if links:
                # For now, we don't know about any properties
                linkspecs = ';'.join([f"{link.metric.bitrate_mbps:.4g}" for link in links])
                column_widths[other_idx] = max(column_widths[other_idx], len(linkspecs))
            else:
                linkspecs = '-'
                # No need to update column_width
            device_linkspecs.append(linkspecs)
        all_linkspecs.append(device_linkspecs)

    column_headers = ["{:^{width}}".format(f"A{device.idx}", width=width)
                      for device, width in zip(network.devices, column_widths)]
    s += f"# {' '.join(column_headers)}\n"
    for device_linkspecs in all_linkspecs:
        formatted_linkspecs = [f"{linkspecs:^{width}}"
                               for linkspecs, width in zip(device_linkspecs, column_widths)]
        # For now, we don't know if it's a switch or an agent. Just make everything an agent.
        s += f"A {' '.join(formatted_linkspecs)}\n"

    return s
