###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import alg_backhaul_switch_rr
import devices
import pytest
import sim
from test_sim import Expect


class Scenario:
    def __init__(self, simulation, checker):
        self.simulation = simulation
        self.checker = checker
        self.last_time = 0  # used by de_activate functions

    def device(self, idx):
        return self.simulation.network.devices[idx]

    def link(self, idx1, idx2):
        return self.device(idx1).links[self.device(idx2)][0]

    def add_de_activate_without_expectation(self, link: devices.Link, activate: bool):
        self.last_time += 1
        sim.set_link_de_activate_event(sim.Tick.s(self.last_time), link, self.simulation, activate)

    def add_de_activate_with_expectation(self, link: devices.Link, activate: bool,
                                         device: devices.Device, new_backhaul: devices.Link):
        self.add_de_activate_without_expectation(link, activate)
        self.checker.add_expectation(sim.Tick.s(self.last_time), 'backhaul switched',
                                     (device, new_backhaul))


@pytest.fixture
def a_scenario():
    """Basic scenario used for these tests.

    - Network with 4 fully connected devices.
    - BackhaulSwitchRR algorithm on each device.
    - Only links to the gateway are active at start.
    - Link between device N and device M > N is in the bridge of device M but not in the bridge of
      device N.
    - Link between device 1 and gateway is deactivated at 1s.
    - Link between device 1 and device 2 is activated at 2s.
    - Link between device 2 and device 3 is activated at 3s.
    - Link between device 2 and gateway is deactivated at 4s.
    """
    network = devices.Network()
    simulation = sim.Simulation(network)
    gateway = network.add_device()
    repeaters = [network.add_device() for _ in range(3)]
    for device in repeaters:
        link_to_gw = device.add_link(gateway, devices.Metric(100))
        link_to_gw.active = True

        for other in repeaters:
            if other == device:
                break
            link_to_other = device.add_link(other, devices.Metric(100))
            link_to_other.active = False
            device.bridged_links.add(link_to_other)

    checker = Expect()

    def notify(when, device, link):
        checker.check_event(when, 'backhaul switched', None, (device, link))

    algorithm = alg_backhaul_switch_rr.AlgBackhaulSwitchRR(simulation, None, notify)
    for device in network.devices:
        simulation.add_algorithm_to_device(algorithm, device)

    for device in repeaters:
        checker.add_expectation(1, 'backhaul switched', (device, device.links[gateway][0]))

    return Scenario(simulation, checker)


def test_alg_backhaul_switch_backup_second(a_scenario):  # noqa: F811
    """No backup when backhaul goes down, it is selected when it comes up later."""

    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 0), False,
                                                a_scenario.device(1), None)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 2), True,
                                                a_scenario.device(1), a_scenario.link(1, 2))

    a_scenario.simulation.run(a_scenario.checker.check_run)
    a_scenario.checker.check_done()


def test_alg_backhaul_switch_backup_first(a_scenario):  # noqa: F811
    """No switching when backup comes up, it is selected when backhaul goes down."""

    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 2), True)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 0), False,
                                                a_scenario.device(1), a_scenario.link(1, 2))

    a_scenario.simulation.run(a_scenario.checker.check_run)
    a_scenario.checker.check_done()


def test_alg_backhaul_switch_skip_bridged(a_scenario):  # noqa: F811
    """A link that is already in the bridge is not used as backup backhaul."""

    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 2), True)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(2, 0), False,
                                                a_scenario.device(2), None)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(2, 3), True,
                                                a_scenario.device(2), a_scenario.link(2, 3))

    a_scenario.simulation.run(a_scenario.checker.check_run)
    a_scenario.checker.check_done()


def test_alg_backhaul_switch_backup_dont_switch_back(a_scenario):  # noqa: F811
    """No switching back when original backhaul becomes live again."""

    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 2), True)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 0), False,
                                                a_scenario.device(1), a_scenario.link(1, 2))
    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 0), True)

    a_scenario.simulation.run(a_scenario.checker.check_run)
    a_scenario.checker.check_done()


def test_alg_backhaul_switch_backup_rr(a_scenario):  # noqa: F811
    """Backup links are iterated round-robin."""

    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 2), True)
    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 3), True)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 0), False,
                                                a_scenario.device(1), a_scenario.link(1, 2))
    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 0), True)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 2), False,
                                                a_scenario.device(1), a_scenario.link(1, 3))
    a_scenario.add_de_activate_without_expectation(a_scenario.link(1, 2), True)
    a_scenario.add_de_activate_with_expectation(a_scenario.link(1, 3), False,
                                                a_scenario.device(1), a_scenario.link(1, 0))

    a_scenario.simulation.run(a_scenario.checker.check_run)
    a_scenario.checker.check_done()
