# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from opts import debug


class HigherLayerDataPayloadTrigger(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        mac_gateway_hex = '0x' + controller.mac.replace(':', '')
        debug("mac_gateway_hex = " + mac_gateway_hex)
        payload = 199 * (mac_gateway_hex + " ") + mac_gateway_hex

        debug("Send Higher Layer Data message")
        # MCUT sends Higher Layer Data message to CTT Agent1 by providing:
        # Higher layer protocol = "0x00"
        # Higher layer payload = 200 concatenated copies of the ALID of the MCUT (1200 octets)
        mid = controller.dev_send_1905(agent.mac, 0x8018,
                                       tlv(0xA0, 0x04b1,
                                           "{0x00 %s}" % payload))

        debug(
            "Confirming higher layer data message was received in one of the agent's radios")

        received_in_radio0, _, _ = self.check_log(
            agent.radios[0],
            r"HIGHER_LAYER_DATA_MESSAGE",
            fail_on_mismatch=False)
        received_in_radio1, _, _ = self.check_log(
            agent.radios[1],
            r"HIGHER_LAYER_DATA_MESSAGE",
            fail_on_mismatch=False)

        number_of_receiving_radios = int(received_in_radio0) + int(
            received_in_radio1)
        if (number_of_receiving_radios != 1):
            self.fail(
                f"higher layer data message was received and acknowledged by "
                f"{number_of_receiving_radios} agent's radios, "
                f"expected exactly 1")

        received_agent_radio = (
            agent.radios[0] if received_in_radio0
            else agent.radios[1])

        debug("Confirming matching protocol and payload length")
        self.check_log(received_agent_radio, r"Protocol: 0")
        self.check_log(received_agent_radio, r"Payload-Length: 0x4b0")

        debug("Confirming ACK message was received in the controller")

        self.check_cmdu_type_single("ACK", 0x8000, agent.mac,
                                    controller.mac, mid)

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
