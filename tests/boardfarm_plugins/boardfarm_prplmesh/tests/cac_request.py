# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
#  from opts import debug
import time


class CacRequest(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        number_of_radios = 1
        operating_class = 121
        channel = 104
        cac_request_tlv = tlv(
                0xAD, 0xA, '0x{:02x} {} 0x{:01x} 0x{:01x} 0x00'
                .format(number_of_radios, agent.radios[1].mac, operating_class, channel))

        print("CAC Request TLV: ", cac_request_tlv)

        req_mid = controller.dev_send_1905(agent.mac, 0x8020, cac_request_tlv)
        time.sleep(1)

        self.check_cmdu_type_single("ACK", 0x8000, agent.mac, controller.mac, req_mid)

        time.sleep(2)

        cac_termination_tlv = tlv(
                0xAE, 0xA, '0x{:02x} {} 0x{:01x} 0x{:01x} 0x00'
                .format(number_of_radios, agent.radios[1].mac, operating_class, channel))

        print("CAC Termination TLV: ", cac_termination_tlv)

        req_mid = controller.dev_send_1905(agent.mac, 0x8021, cac_termination_tlv)
        time.sleep(1)

        self.check_cmdu_type_single("ACK", 0x8000, agent.mac, controller.mac, req_mid)

        # TODO
        # verify that the agent sends beacons

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
