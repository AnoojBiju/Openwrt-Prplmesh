# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from boardfarm.exceptions import SkipTest
from capi import tlv
from common_flow import CommonFlows
from time import sleep


class V2Certification_4_7_10(CommonFlows):

    def runTest(self):
        # Locate test participants
        try:
            sta1 = self.dev.wifi
            sta2 = self.get_device_by_name('wifi2')
            sta3 = self.get_device_by_name('wifi3')

            controller = self.dev.lan.controller_entity

            agent = self.dev.DUT.agent_entity

            vap1 = agent.radios[0].vaps[0]
            vap2 = agent.radios[1].vaps[0]
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        # Phase 2 (step 3)
        mid = controller.dev_send_1905(agent.mac, 0x8001)
        # wait
        sleep(1)
        # Phase 2 (step 4)
        '''
        Todo:
        Verify that MAUT sends a correctly formatted AP Capability Report message within 1 sec of
        receiving the AP Capability Query message sent by the Controller.
        Verify that the AP Capability Report message contains one Metric Collection Interval TLV and
        one R2 AP Capability TLV with the Byte Counter Units field set to 0x01.
        '''
        resp = self.check_cmdu_type_single("AP Capability Report message", 0x8002,
                                           agent.mac, controller.mac,
                                           mid)

        self.check_cmdu_has_tlvs(resp, 0xC5)
        ap_capability_tlv = self.check_cmdu_has_tlvs(resp, 0xB4)
        print(ap_capability_tlv)

        # Phase 3
        # Phase 4
        vap1.associate(sta1)
        vap1.associate(sta3)
        vap2.associate(sta2)

        sleep(1)
        # Phase 5
        # Phase 6

        # Phase 7

        # prepare tlvs
        sta_mac_addr_tlv = tlv(0x95, 0x0006, '{}'.format(sta2.mac))
        # send
        mid = controller.dev_send_1905(agent.mac, 0x800D, sta_mac_addr_tlv)
        # wait
        sleep(5)
        # check response
        resp = self.check_cmdu_type_single("associated sta link metrics response", 0x800E,
                                           agent.mac, controller.mac,
                                           mid)
        self.check_cmdu_has_tlvs(resp, 0xC8)
        self.check_cmdu_has_tlvs(resp, 0x96)

        # Phases 9 + 10

        # Disable reporting
        self.configure_multi_ap_policy_config_with_unsuccessful_association(agent, controller,
                                                                            0x00, 0x00)
        # report should not be sent as we disabled the feature
        self.mismatch_psk(agent.radios[0], controller, sta1, 'no')

        # Enable unsuccsfull association - 1 per minute
        self.configure_multi_ap_policy_config_with_unsuccessful_association(agent, controller,
                                                                            0x80, 0x01)
        # First report should be sent
        self.mismatch_psk(agent.radios[0], controller, sta1, 'yes')

        # tear down the test: disassociated
        vap1.disassociate(sta1)
        vap1.disassociate(sta3)
        vap2.disassociate(sta2)

        # reset everything
        controller.cmd_reply("DEV_RESET_DEFAULT")

        # wait
        sleep(2)

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
