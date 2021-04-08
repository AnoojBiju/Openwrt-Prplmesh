###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import collections
from devices import Network
import logging
from sim import Tick
from typing import Any


class CheckerDisconnect():
    """Checker for network connectivity.

    This simulation checker keeps track of when a device is disconnected from the gateway, and how
    long it remains disconnected. Finally it reports the results.

    It can be used as the checker argument to sim.Simulation.run().

    Attributes
    ----------
    disconnect_times: Dict[Device, List[(Tick, Union[Tick, None])]]
        Keeps track of the times that a device was disconnected and when it connected again. If end
        is None, it is still disconnected at the end of the simulation.
    """

    def __init__(self):
        self.disconnect_times = collections.defaultdict(list)

    def __call__(self, when: Tick, network: Network, last_event: Any):
        """Checker function.

        Checks if all devices in the network are conneced to the gateway. Keeps track of the time
        that devices were not connected.
        """
        backhaul_tree = network.calculate_backhaul_tree()
        for device in network.devices:
            disconnect_times = self.disconnect_times[device]
            if disconnect_times:
                start, end = disconnect_times[-1]
                if end:
                    start = None
            else:
                start = None
            logging.debug(f"@{when} {device} start {start} connected {device in backhaul_tree}")
            if device in backhaul_tree:
                if start is not None:
                    logging.debug(f"{device} was disconnected at {start}, connected at {when}")
                    disconnect_times[-1] = (start, when)
                # else was already connected before
            else:
                if start is None:
                    logging.debug(f"{device} disconnected at {when}")
                    disconnect_times.append((when, None))
                # else was already disconnected before

    def report(self) -> str:
        """Report the disconnect times of devices."""
        ret = ""
        for device, disconnect_times in self.disconnect_times.items():
            if not disconnect_times:
                continue
            ret += f"{device} disconnected "
            ret += ", ".join([f"{start}-{end or ''}" for start, end in disconnect_times])
            ret += "\n"
        return ret
