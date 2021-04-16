###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import collections
import devices
import pytest
import sim
from test_devices import a_network, chain_network, tree_network  # noqa: F401
from typing import Any, Union


@pytest.fixture
def a_simulation(chain_network):  # noqa: F811
    simulation = sim.Simulation(chain_network)
    return simulation


@pytest.fixture
def a_message():
    return devices.Message('TestMessage', 'TestPayload')


class Expect:
    '''Helper class that registers expectations.'''
    def __init__(self):
        '''Create checker.'''
        self.expectations = collections.defaultdict(list)  # Tick -> [(what, arg)]
        self.last_when = -1
        self.last_event = None

    def add_expectation(self, when: Union[sim.Tick, int], what: str, arg: Any = None):
        '''Add an expectation to the checker.

        Parameters
        ----------
        when: Union[Tick, int]
            When the event is expected
        what: str
            What kind of event is expected
        arg: Any
            An object argument associated with the event.
        '''
        self.expectations[sim.Tick(when)].append((what, arg))

    def check_event(self, when, what, description, arg):
        when_expectations = self.expectations[when]
        assert when_expectations, f"@{when} Unexpected event {what} {description}"
        assert (what, arg) in when_expectations, f"@{when} Unexpected event {what} {description}," \
                                                 f" expected {len(when_expectations)} others"
        when_expectations.remove((what, arg))
        if not when_expectations:
            del self.expectations[when]  # Allows us to use `not self.expectations` in check_done
        self.last_when = when
        self.last_event = description

    def event_callback(self, when, description):
        self.check_event(when, 'event', description, None)

    def timeout_callback(self, when, device, description):
        self.check_event(when, 'timeout', description, device)

    def check_run(self, when, network, last_event):
        if self.last_event:
            assert when == self.last_when
            assert last_event == self.last_event
        self.last_event = None

    def check_done(self):
        assert not self.expectations


class AlgorithmTest(sim.Algorithm):
    def __init__(self, simulation, checker):
        super().__init__('TestAlgorithm', simulation)
        self.checker = checker

    def start(self, when: float, device: sim.Device):
        self.checker.check_event(when, 'start', f'{device}_{self.name}_Startup', device)
        self.set_timeout(sim.Tick.s(-1.0), device, self.checker.timeout_callback)

    def handle_link_activate(self, when, device, link, active):
        description = "Activate" if active else "Deactivate"
        self.checker.check_event(when, 'activate', description, (device, link, active))


def test_simulation_event(a_simulation):
    checker = Expect()
    checker.add_expectation(sim.Tick.s(0.5), 'event', None)
    a_simulation.add_event(sim.Tick.s(0.5), checker.event_callback)
    a_simulation.run(checker.check_run)
    checker.check_done()


def test_simulation_start_and_timeout(a_simulation):
    checker = Expect()
    algorithm = AlgorithmTest(a_simulation, checker)
    for idx, device in enumerate(a_simulation.network.devices):
        a_simulation.add_algorithm_to_device(algorithm, device)
        checker.add_expectation(1, 'start', device)
        checker.add_expectation(sim.Tick.s(1.0) + 1, 'timeout', device)

    d3, d4 = a_simulation.network.devices[3:5]
    link = d3.links[d4][0]
    sim.set_link_de_activate_event(sim.Tick.s(2), link, a_simulation, False)
    checker.add_expectation(sim.Tick.s(2), 'activate', (d3, link, False))
    checker.add_expectation(sim.Tick.s(2), 'activate', (d4, link, False))
    sim.set_link_de_activate_event(sim.Tick.s(3), link, a_simulation, True)
    checker.add_expectation(sim.Tick.s(3), 'activate', (d3, link, True))
    checker.add_expectation(sim.Tick.s(3), 'activate', (d4, link, True))

    a_simulation.run(checker.check_run)
    checker.check_done()


class AlgorithmTestMessage(sim.Algorithm):
    def __init__(self, simulation, checker):
        super().__init__('TestMessageAlgorithm', simulation)
        self.checker = checker

    def handle_message(self, when, device, message, src, dst, src_link):
        assert message.msg_type == 'TestMessage'
        self.checker.check_event(when, 'message', None, (src, dst, device))


def test_message_unicast(tree_network, a_message):  # noqa: F811
    simulation = sim.Simulation(tree_network)
    checker = Expect()
    algorithm = AlgorithmTestMessage(simulation, checker)
    for device in tree_network.devices:
        simulation.add_algorithm_to_device(algorithm, device)

    # Path is d5 -> d2 -> d0 -> d1 -> d3 so 4 hops
    src = tree_network.devices[5]
    dst = tree_network.devices[4]
    checker.add_expectation(4, 'message', (src, dst, dst))
    sim.send_msg(a_message, src, dst, simulation)
    simulation.run(checker.check_run)
    checker.check_done()


def test_message_multicast(a_simulation, a_message):  # noqa: F811
    checker = Expect()
    algorithm = AlgorithmTestMessage(a_simulation, checker)
    src = a_simulation.network.devices[0]
    for idx, device in enumerate(a_simulation.network.devices):
        a_simulation.add_algorithm_to_device(algorithm, device)
        checker.add_expectation(idx, 'message', (src, None, device))

    sim.send_msg(a_message, src, None, a_simulation)
    a_simulation.run(checker.check_run)
    checker.check_done()


def test_message_unicast_broken_link(a_simulation, a_message):  # noqa: F811
    checker = Expect()
    algorithm = AlgorithmTestMessage(a_simulation, checker)
    for device in a_simulation.network.devices:
        a_simulation.add_algorithm_to_device(algorithm, device)

    a_simulation.network.devices[3].links[a_simulation.network.devices[2]][0].active = False
    # Message is expected *not* to arrive
    sim.send_msg(a_message, a_simulation.network.devices[0], a_simulation.network.devices[5],
                 a_simulation)
    a_simulation.run(checker.check_run)
    checker.check_done()
