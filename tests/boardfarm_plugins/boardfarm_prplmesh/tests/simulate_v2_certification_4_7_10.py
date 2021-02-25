# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from boardfarm.exceptions import SkipTest
from capi import tlv
from common_flow import CommonFlows
from time import sleep


class V2Certification_4_7_10(CommonFlows):
    """
        Devices used in test setup:
        STA1 - WIFI repeater
        STA2 - WIFI repeater
        STA3 - WIFI repeater
        AP1 - Agent1 [DUT]
        GW - Controller
    """

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
        Verify that MAUT sends a correctly formatted AP Capability Report message within 1 sec of
        receiving the AP Capability Query message sent by the Controller.
        Verify that the AP Capability Report message contains
            one Metric Collection Interval TLV and
            one R2 AP Capability TLV with the Byte Counter Units field set to 0x01.
        '''
        resp = self.check_cmdu_type_single("AP Capability Report message", 0x8002,
                                           agent.mac, controller.mac, mid)
        self.check_cmdu_has_tlvs(resp, 0xB4)
        self.check_cmdu_has_tlvs(resp, 0xC5)

        # Phase 3
        # Phase 4
        sta1.wifi_connect(vap1)
        sta2.wifi_connect(vap2)
        sta3.wifi_connect(vap1)

        sleep(1)
        # Phase 5
        # Phase 6

        '''
        Trigger (DEV_SEND_1905, DestALid, WTS_REPLACE_MAUT_ALID, MessageTypeValue,0x8003)
        CTT Controller to send a Multi-AP Policy Config Request message to MAUT,
        containing:
        a) a Metric Reporting Policy TLV: (
                AP Metric Reporting Interval = 10;
                Number of Radios =1; (
                    RUID=WTS_REPLACE_RUID
                    STA Metrics Reporting RCPI Threshold = 0;
                    AP Metrics Channel Utilization Reporting Threshold.= 0;
                    STA Metrics Reporting RCPI Hysteresis Margin Override = 0;
                    AP Metrics Channel Utilization Reporting Threshold = 0;
                    Associated STA Traffic Stats Inclusion Policy = 1;
                    Associated STA Link Metrics Inclusion Policy = 1
                );
                and
        b) an Unsuccessful Association Policy TLV: (
                Report Unsuccessful Associations = 1;
                Maximum Reporting Rate = 60
            )
        '''

        metric_reporting_policy_tlv = tlv(0x8A, 0x000D,
                                          '0x0a 0x01 {} 0x00 0x00 0x00 0x00 0x0f'
                                          .format(agent.radios[0].mac))
        unsuccessful_association_policy_tlv = tlv(0xC4, 0x0005, '0x01 0x0000003c')

        mid = controller.dev_send_1905(agent.mac, 0x8003,
                                       metric_reporting_policy_tlv,
                                       unsuccessful_association_policy_tlv)

        sleep(1)
        self.check_cmdu_type_single("ACK", 0x8000, agent.mac, controller.mac, mid)

        sleep(12)  # TIME_METRICS value in test suite v2.

        response = self.check_cmdu_type_single("AP metrics response", 0x800C,
                                               agent.mac, controller.mac)

        '''
        AP Metrics Response message containing
            one AP Metrics TLV and
            one AP Extended Metrics TLV for each of the two fronthaul BSSes and
            one Radio Metrics TLV for the fronthaul radio and
            one Associated STA Traffic Stats TLV,
            one Associated STA Link Metrics TLV and
            one Associated STA Extended Link Metrics TLV for each of
                CTT STA 1, CTT STA 2 and CTT STA 3.
        '''

        # one Radio Metrics TLV for the fronthaul radio and <-- we check only this at the moment
        self.check_cmdu_has_tlvs(response, 0xC6)

        # Phase 7

        # Phase 8

        # prepare tlvs
        sta_mac_addr_tlv = tlv(0x95, 0x0006, '{}'.format(sta2.mac))
        # send
        mid = controller.dev_send_1905(agent.mac, 0x800D, sta_mac_addr_tlv)
        # wait
        sleep(5)
        # check response
        associated_link_metrics_resp = self.check_cmdu_type_single(
                                            "associated sta link metrics response", 0x800E,
                                            agent.mac, controller.mac, mid)
        self.check_cmdu_has_tlvs(associated_link_metrics_resp, 0xC8)
        self.check_cmdu_has_tlvs(associated_link_metrics_resp, 0x96)

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
        sta1.wifi_disconnect(vap1)
        sta2.wifi_disconnect(vap2)
        sta3.wifi_disconnect(vap1)

        # reset everything
        controller.cmd_reply("DEV_RESET_DEFAULT")

        # wait
        sleep(2)
