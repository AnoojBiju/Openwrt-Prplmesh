# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from opts import debug

import time


class MultiApPolicyConfigWSteeringPolicy(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        debug("Send multi-ap policy config request with steering policy to agent 1")
        mid = controller.dev_send_1905(agent.mac, 0x8003,
                                             tlv(0x89, 0x000C, "{0x00 0x00 0x01 {%s 0x01 0xFF 0x14}}" % agent.radios[0].mac))  # noqa E501
        time.sleep(1)
        debug("Confirming multi-ap policy config request has been received on agent")

        self.check_cmdu_type("MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE", 0x8003,
                             controller.mac, agent.mac, mid)

        time.sleep(1)
        debug("Confirming multi-ap policy config ack message has been received on the controller")
        self.check_cmdu_type_single("ACK", 0x8000, agent.mac, controller.mac, mid)

    @classmethod
    def teardown_class(cls):
        """Teardown method, optional for boardfarm tests."""
        test = cls.test_obj
        print("Sniffer - stop")
        test.dev.DUT.wired_sniffer.stop()
        # Send additional Ctrl+C to the device to terminate "tail -f"
        # Which is used to read log from device. Required only for tests on HW
        try:
            test.dev.DUT.agent_entity.device.send('\003')
        except AttributeError:
            # If AttributeError was raised - we are dealing with dummy devices.
            # We don't have to additionaly send Ctrl+C for dummy devices.
            pass
        test.dev.wifi.disable_wifi()
