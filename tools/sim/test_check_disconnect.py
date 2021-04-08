###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import check_disconnect
import logging
import sim
from test_sim import a_simulation, chain_network, a_network  # noqa: F401


def test_checker_disconnect(a_simulation):  # noqa: F811
    checker = check_disconnect.CheckerDisconnect()
    a_link = a_simulation.network.devices[3].links[a_simulation.network.devices[4]][0]

    sim.set_link_de_activate_event(sim.Tick.s(3), a_link, a_simulation, False)
    sim.set_link_de_activate_event(sim.Tick.s(14), a_link, a_simulation, True)
    sim.set_link_de_activate_event(sim.Tick.s(15), a_link, a_simulation, False)

    a_simulation.run(checker)

    logging.info("Disconnect report: \n" + checker.report())

    for idx, device in enumerate(a_simulation.network.devices):
        disconnect_times = checker.disconnect_times[device]
        if idx < 4:
            assert not disconnect_times
        else:
            assert disconnect_times[0] == (sim.Tick.s(3), sim.Tick.s(14))
            assert disconnect_times[1] == (sim.Tick.s(15), None)
            assert len(disconnect_times) == 2
