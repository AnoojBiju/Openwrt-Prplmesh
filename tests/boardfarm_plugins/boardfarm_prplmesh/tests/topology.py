# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug

import time


class Topology(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        # Agent Topology updated when Controller gets Topology Discovery
        # (which is sent every 60 sec.)
        time.sleep(61)

        # Send Topology Query
        controller.dev_send_1905(agent.mac, 0x0002)
        time.sleep(1)

        debug("\nAfter Topology Query Message:\nCurrent network topology:")
        topology = self.get_topology()
        for value in topology.values():
            debug(value)

        debug("Confirming Controller MAC appears on Agent Interface Neighbors")
        found = False
        map_agent = topology[agent.mac]
        for map_interface in map_agent.interfaces.values():
            for map_neighbor in map_interface.neighbors:
                if map_neighbor == controller.mac:
                    found = True

        assert found, \
            "Controller MAC " + controller.mac + "is not found in Neighbor List"

    @classmethod
    def teardown_class(cls):
        """Teardown method, optional for boardfarm tests."""
        test = cls.test_obj
        # Send additional Ctrl+C to the device to terminate "tail -f"
        # Which is used to read log from device. Required only for tests on HW
        try:
            test.dev.DUT.agent_entity.device.send('\003')
        except AttributeError:
            # If AttributeError was raised - we are dealing with dummy devices.
            # We don't have to additionally send Ctrl+C for dummy devices.
            pass
        test.dev.wifi.disable_wifi()
