# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from opts import debug


class ClientAssociation(PrplMeshBaseTest):
    """
        Devices used in test setup:
        STA1 - WIFI repeater
        AP1 - Agent1 [DUT]
        GW - Controller

        Topology request is sent to AP1
        AP1 logs are checked if topology query was received
        Client association control message is sent to AP1
        AP1 logs are checked if client association control message has been received
        GW controller if checked for a ACK message
    """

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity

            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        debug("Send topology request to agent 1")
        controller.dev_send_1905(agent.mac, 0x0002)
        debug("Confirming topology query was received")
        self.check_log(agent, r"TOPOLOGY_QUERY_MESSAGE")

        debug("Send client association control message")
        controller.dev_send_1905(agent.mac, 0x8016,
                                       tlv(0x9D, 0x000F,
                                           "{%s 0x00 0x1E 0x01 {0x000000110022}}" % agent.radios[0].mac))  # noqa E501

        debug("Confirming client association control message has been received on agent")
        # check that both radio agents received it,in the future we'll add a check to verify which
        # radio the query was intended for.
        self.check_log(agent.radios[0], r"CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE")
        self.check_log(agent.radios[1], r"CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE")

        debug("Confirming ACK message was received on controller")
        self.check_log(controller, r"ACK_MESSAGE")

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
            # We don't have to additionaly send Ctrl+C for dummy devices.
            pass
        test.dev.wifi.disable_wifi()
