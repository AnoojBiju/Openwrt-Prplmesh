###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

"""Algorithm for backhaul switching - simple round-robin.

This module implements a simple round-robin algorithm for backhaul switching.
"""

from devices import Device, Link
import itertools
import logging
from sim import Algorithm, Simulation, Tick
from typing import Callable, List, Optional


class AlgBackhaulSwitchRR(Algorithm):
    """Simple round-robin algorithm for backhaul switching.

    This algorithm keeps track of a single upstream backhaul link. When that backhaul link is
    deactivated, it tries a different backhaul link in a round-robin fashion.

    This algorithm only reacts on the immediate backhaul link deactivation. It doesn't detect when
    a link further uptream is deactivated. However, it can be combined with other algorithms that
    detect such a thing - this other algorithm can call switch_backhaul to force a switch. That
    function can also be called if the backhaul is switched for some other reason (e.g. backhaul
    optimisation).

    The algorithm also reacts to link activation, but only if there is no backhaul link at the
    moment. In that case, activation of any link will trigger switch_backhaul. Note that due
    to backhaul_links_generator (see below), it is still possible that no backhaul can be found
    because the activated link is not a candidate.

    This algorithm needs to distinguish candidate upstream links from downstream links. By default,
    it treats all active links as candidates. If there are multiple paths to the gateway, that
    means that it may choose a backhaul link that creates a loop in the network. Therefore, this
    algorithm needs to be combined with an algorithm that does loop avoidance. The latter can either
    deactivate the link(s) that shouldn't be used, or it can install the backhaul_links_generator
    callback that returns a list of candidate links.

    The round robin algorithm takes the list of candidate links, finds the current backhaul link in
    it, and selects the next link that is active.

    If no approprate link can be found, the device is left without backhaul link.

    This algorithm adds one attribute to the devices it controls:

    backhaul_link: Optional[Link]
        The current backhaul link.

    Parameters
    ----------
    simulation: Simulation
        The Simulation to which this algorithm belongs. Used for creating events.
    backhaul_links_generator: Callable[[Tick, Device], List[Link]], optional
        If set, this callback is called to get the list of candidate backhaul links. If not set,
        all the device's links are used. Parameters: when: time of the query; device: device on
        which the switch happens. Returns: list of links (on the device) that are candidate
        backhaul links.
    notify: Callable[[Tick, Device, Link], None], optional
        If set, this callback is called when the backhaul link is switched. Parameters: when: time
        of the switch; device: on which device the switch happens; link: the new backhaul link.
    """

    def __init__(self, simulation: Simulation,
                 backhaul_links_generator: Optional[Callable[[Tick, Device], List[Link]]] = None,
                 notify: Optional[Callable[[Tick, Device, Optional[Link]], None]] = None):
        self.backhaul_links_generator = backhaul_links_generator or self._all_backhaul_links
        self.notify = notify
        super().__init__("BackhaulSwitchRR", simulation)

    def start(self, when: Tick, device: Device):
        device.backhaul_link = None
        self.switch_backhaul(when, device)

    def handle_link_activate(self, when: Tick, device: Device, link: Link, active: bool):
        if active and not device.backhaul_link:
            self.switch_backhaul(when, device)
        elif not active and device.backhaul_link == link:
            self.switch_backhaul(when, device)

    def switch_backhaul(self, when: Tick, device: Device, new_backhaul: Optional[Link] = None) \
            -> Optional[Link]:
        """Trigger backhaul switching.

        This triggers the backhaul switching algorithm.

        First, the candidates are collected with backhaul_links_generator.

        If `new_backhaul` is set, that one is used as the new backhaul link, otherwise the next link
        after the current one. If there is not current one, the first one is used. If the new link
        is not active, the next one is tried until an active one is found.

        Finally, if any switching actually takes place, the notify callback is called with the new
        link. If no new backhaul link could be established, the notify callback is still called but
        with None as the link.

        This method is called automatically when the current backhaul link is deactivated, or when
        there is no current backhaul link and one of the device's links is activated.

        Parameters
        ----------
        when: Tick
            The time of the switch.
        device: Device
            The device on which the switch happens
        new_backhaul: Link, optional
            If set, this is the first candidate rather than the first one after the current.

        Returns
        -------
        Link, optional
            The new backhaul link, or None if none found.
        """
        logging.debug(f"@{when} switch backhaul on {device}" +
                      (f" to {new_backhaul}" if new_backhaul else ""))
        # Gateway never switches
        if device.idx == 0:
            return

        if device.backhaul_link:
            if device.backhaul_link in device.bridged_links:
                device.bridged_links.remove(device.backhaul_link)
            else:
                logging.warning(f"@{when} switch backhaul on {device},"
                                f" old backhaul {device.backhaul_link} not in bridge")

        candidates = list(self.backhaul_links_generator(when, device))

        if new_backhaul:
            if not new_backhaul.active:
                logging.warning(f"@{when} switch backhaul on {device} to {new_backhaul}"
                                f" but is not active.")
        else:
            if device.backhaul_link and device.backhaul_link in candidates:
                idx = candidates.index(device.backhaul_link)
                del candidates[idx]
                # By removing the current one, idx now points to the next one or beyond the end.
                if idx >= len(candidates):
                    idx = 0
            else:
                idx = 0
            if candidates:
                new_backhaul = candidates[idx]

        if new_backhaul:
            # Move everything before new_backhaul to the end of the list
            idx = candidates.index(new_backhaul)
            candidates.extend(candidates[:idx])
            del candidates[:idx]

            assert new_backhaul == candidates[0]

            for new_backhaul in candidates:
                logging.debug(f"Considering {new_backhaul} active {new_backhaul.active}"
                              f" bridge {new_backhaul in device.bridged_links}")
                if new_backhaul not in device.bridged_links and \
                   new_backhaul.active:
                    break
            else:
                logging.info(f"@{when} switch backhaul on {device}, no new backhaul found in"
                             f" {len(candidates)} candidates")
                new_backhaul = None

        logging.info(f"@{when} switch backhaul on {device} from {device.backhaul_link} to "
                     f"{new_backhaul}")

        if device.backhaul_link != new_backhaul and self.notify:
            self.notify(when, device, new_backhaul)

        device.backhaul_link = new_backhaul
        if new_backhaul:
            device.bridged_links.add(new_backhaul)
        return new_backhaul

    def _all_backhaul_links(self, when: Tick, device: Device) -> List[Link]:
        """Default backhaul links generator - return all links."""
        return itertools.chain(*device.links.values())
