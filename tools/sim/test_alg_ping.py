###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import alg_ping
import sim
from test_sim import Expect, a_simulation, chain_network, a_network  # noqa: F401


def test_alg_ping(a_simulation):  # noqa: F811
    checker = Expect()

    def handler(when, device, simulation, connected):
        checker.check_event(when, '(dis)connected', None, (device, connected))

    algorithm = alg_ping.AlgPingController(sim.Tick.s(10), a_simulation, handler)
    for device in a_simulation.network.devices:
        a_simulation.add_algorithm_to_device(algorithm, device)

    a_link = a_simulation.network.devices[3].links[a_simulation.network.devices[4]][0]

    sim.set_link_de_activate_event(sim.Tick.s(15), a_link, a_simulation, False)
    checker.add_expectation(sim.Tick.s(21) + 1, '(dis)connected',
                            (a_simulation.network.devices[4], False))
    checker.add_expectation(sim.Tick.s(21) + 1, '(dis)connected',
                            (a_simulation.network.devices[5], False))
    sim.set_link_de_activate_event(sim.Tick.s(30.1), a_link, a_simulation, True)
    checker.add_expectation(sim.Tick.s(40) + 9, '(dis)connected',
                            (a_simulation.network.devices[4], True))
    checker.add_expectation(sim.Tick.s(40) + 11, '(dis)connected',
                            (a_simulation.network.devices[5], True))

    a_simulation.run(checker.check_run, sim.Tick.s(50))
    checker.check_done()
