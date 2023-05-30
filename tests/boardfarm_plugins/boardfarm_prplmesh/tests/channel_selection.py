###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020-2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from environment import ChannelTlvs
from opts import debug


class ChannelSelection(PrplMeshBaseTest):
    """
    Devices used in test setup:
            AP1 - Agent1 [DUT]
            GW - Controller

    Check if the channel is switched when there's a channel preference but
     an empty channel selection request
    - Should fail if channels are different
    Check if the channel is switched when there's an empty channel selection
     request changing tx_power_limit
    - Should fail if channels are different
    Trigger channel selection to channel 6 (2.4GHz), 36 (5GHz) and 109 (6GHz).
     Check that operating channel report was sent.
    - Should fail if channels haven't changed to 6, 36 and 109.
    """

    def runTest(self):

        def check_single_channel_response(self, resp_code) -> None:
            cs_resp = self.check_cmdu_type_single("channel selection response",
            self.ieee1905['eMessageType']['CHANNEL_SELECTION_RESPONSE_MESSAGE'],
            agent.mac, controller.mac, cs_req_mid)  # noqa E501
            if cs_resp:
                cs_resp_tlvs = self.check_cmdu_has_tlvs(cs_resp, 0x8e)
                radio_macs = [radio.mac for radio in agent.radios]

                for cs_resp_tlv in cs_resp_tlvs:
                    if cs_resp_tlv.channel_select_radio_id not in radio_macs:
                        if int(cs_resp_tlv.channel_select_response_code, 16) != resp_code:
                            self.fail("Unexpected radio ID {}, expecting one of {}\n"
                                      "Channel selection unexpected response code {}".format(
                                cs_resp_tlv.channel_select_radio_id,  # noqa E501
                                ", ".join(radio_macs),
                                cs_resp_tlv.channel_select_response_code
                            ))
                        self.fail("Unexpected radio ID {}, expecting one of {}".format(
                            cs_resp_tlv.channel_select_radio_id,
                            ", ".join(radio_macs)))

        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        self.configure_ssids(['ChannelSelection'])

        self.checkpoint()

        orig_channels_lst = []
        for radio in agent.radios:
            orig_channels_lst.append(radio.get_current_channel())

        starting_channels_str = "Starting channel "
        for idx, orig_chan in enumerate(orig_channels_lst):
            starting_channels_str += "wlan{}: {}, ".format(idx * 2, orig_chan)
        starting_channels_str = starting_channels_str[:-2]
        debug(starting_channels_str)

        debug("Send channel preference query")
        ch_pref_query_mid = controller.dev_send_1905(agent.mac,
                                                     self.ieee1905['eMessageType']
                                                     ['CHANNEL_PREFERENCE_QUERY_MESSAGE'])
        time.sleep(3)
        debug("Confirming channel preference query has been received on agent")

        self.check_cmdu_type_single("Channel Preference Report",
                                    self.ieee1905['eMessageType']
                                    ['CHANNEL_PREFERENCE_REPORT_MESSAGE'],
                                    agent.mac,
                                    controller.mac, ch_pref_query_mid)

        debug("Send empty channel selection request")
        cs_req_mid = controller.dev_send_1905(agent.mac,
                                              self.ieee1905['eMessageType']
                                              ['CHANNEL_SELECTION_REQUEST_MESSAGE'],
                                              tlv(0x00, "{}"))

        time.sleep(1)

        check_single_channel_response(self, 0x00)

        cur_channels_lst = []
        for radio in agent.radios:
            cur_channels_lst.append(radio.get_current_channel())

        for i in range(len(orig_channels_lst)):
            if cur_channels_lst[i] != orig_channels_lst[i]:
                self.fail("Radio {} channel switched to {}".format(i, cur_channels_lst[i]))

        oper_channel_reports = self.check_cmdu_type("operating channel report",
                                                    self.ieee1905['eMessageType']
                                                    ['OPERATING_CHANNEL_REPORT_MESSAGE'],
                                                    agent.mac, controller.mac)
        for report in oper_channel_reports:
            self.check_cmdu_type_single("ACK", self.ieee1905['eMessageType']['ACK_MESSAGE'],
                                        controller.mac, agent.mac,
                                        report.ieee1905_mid)

        self.checkpoint()

        tp16dBm = 0x10
        tp17dBm = 0x11

        for payload_transmit_power in (tp16dBm, tp17dBm):
            debug("Send empty channel selection request with changing tx_power_limit")

            tx_power_limit_tlvs_lst = []
            for i in range(len(agent.radios)):
                tx_power_limit_tlvs_lst.append(tlv(self.ieee1905['eTlvTypeMap']
                                                   ['TLV_TRANSMIT_POWER_LIMIT'],
                                                   '{} 0x{:02x}'.format(agent.radios[i].mac,
                                                                        payload_transmit_power)))
            cs_req_mid = controller.dev_send_1905(
                agent.mac,
                self.ieee1905['eMessageType']['CHANNEL_SELECTION_REQUEST_MESSAGE'],
                *tx_power_limit_tlvs_lst)
            time.sleep(1)

            cur_power_lst = []
            for radio in agent.radios:
                cur_power_lst.append(radio.get_power_limit())

            for idx, cur_power in enumerate(cur_power_lst):
                if cur_power != payload_transmit_power:
                    self.fail("Radio {} tx_power swithed to {}".format(idx, cur_power))

            self.check_cmdu_type_single("Channel Selection Response",
                                        self.ieee1905['eMessageType']
                                        ['CHANNEL_SELECTION_RESPONSE_MESSAGE'],
                                        agent.mac,
                                        controller.mac, cs_req_mid)

            cur_channels_lst = []
            for radio in agent.radios:
                cur_channels_lst.append(radio.get_current_channel())

            cur_channels_lst = []
            for radio in agent.radios:
                cur_channels_lst.append(radio.get_current_channel())

            for i in range(len(orig_channels_lst)):
                if cur_channels_lst[i] != orig_channels_lst[i]:
                    self.fail("Radio {} channel switched to {}".format(i, cur_channels_lst[i]))

            oper_channel_reports = self.check_cmdu_type("operating channel report",
                                                        self.ieee1905['eMessageType']
                                                        ['OPERATING_CHANNEL_REPORT_MESSAGE'],
                                                        agent.mac, controller.mac)
            for report in oper_channel_reports:
                for ocr in report.ieee1905_tlvs:
                    if ocr.tlv_type != 0x8F:
                        self.fail("Unexpected TLV in operating channel report: {}".format(ocr))
                        continue
                    if int(ocr.operating_channel_eirp) != payload_transmit_power:
                        self.fail("Unexpected transmit power {} instead of {} for {}".format(
                            ocr.operating_channel_eirp, payload_transmit_power,
                            ocr.operating_channel_radio_id))
                self.check_cmdu_type_single("ACK",
                                            self.ieee1905['eMessageType']['ACK_MESSAGE'],
                                            controller.mac, agent.mac,
                                            report.ieee1905_mid)

            self.checkpoint()

        debug("Send invalid channel selection request to radio 0")
        cs_req_mid = controller.dev_send_1905(
            agent.mac, self.ieee1905['eMessageType']['CHANNEL_SELECTION_REQUEST_MESSAGE'],
            # Single operating class with a single channel that doesn't exist in it.
            tlv(self.ieee1905['eTlvTypeMap']['TLV_CHANNEL_PREFERENCE'],
                agent.mac + ' 0x01 {0x52 {0x01 {0x01}} 0x00}'))
        time.sleep(1)

        check_single_channel_response(self, f"""0x{self.ieee1905['tlvChannelPreference']
                                     ['ePreference']['PREFERRED2']:02x}""")

        self.checkpoint()

        # payload_wlan0 - request for change channel on 6
        payload_wlan0 = ChannelTlvs.CHANNEL_6.value

        # payload_wlan2  - request for change channel on 36
        payload_wlan2 = ChannelTlvs.CHANNEL_36.value

        # payload_wlan4  - request for change channel on 109
        payload_wlan4 = ChannelTlvs.CHANNEL_109.value

        channel_preference_payloads = []
        channel_preference_payloads.append(payload_wlan0)
        channel_preference_payloads.append(payload_wlan2)
        if len(agent.radios) > 2:
            channel_preference_payloads.append(payload_wlan4)

        """
        Step 1: Trigger channel selection to channel 6, 36 and 109. Check that
                operating channel report was sent.

        Step 2: Trigger channel selection to channel 6, 36 and 109 again - check that
                operating channel report is sent again. This is to catch bugs
                when we don't send channel report when there is no need to
                switch channel
        """
        for i in range(1, 3):
            debug("Send channel selection request, step {}".format(i))

            channel_selection_tlvs = []
            for idx, payload in enumerate(channel_preference_payloads):
                channel_selection_tlvs.append(tlv(self.ieee1905['eTlvTypeMap']
                                                  ['TLV_CHANNEL_PREFERENCE'],
                                                  '{} {}'.format(agent.radios[idx].mac, payload)))
                channel_selection_tlvs.append(tlv(self.ieee1905['eTlvTypeMap']
                                                  ['TLV_TRANSMIT_POWER_LIMIT'],
                                                  '{} 0x{:2x}'.format(agent.radios[idx].mac,
                                                                      tp16dBm)))

            cs_req_mid = controller.dev_send_1905(agent.mac, 0x8006, *channel_selection_tlvs)
            time.sleep(1)

            debug("Confirming tlvTransmitPowerLimit has been received with correct value on agent,"
                  " step {}".format(i))

            cur_power_lst = []
            for radio in agent.radios:
                cur_power_lst.append(radio.get_power_limit())

            for idx, cur_power in enumerate(cur_power_lst):
                if cur_power != tp16dBm:
                    self.fail("Radio {} tx_power swithed to {}".format(idx, cur_power))

            check_single_channel_response(self, 0x00)

            # payload_wlan0, payload_wlan2 and payload_wlan4 (if existed) forced to
            # channel 6, 36, 109 resp. check that this happened
            expected_channels = [6, 36, 109]
            for i in range(len(agent.radios)):
                (cur_chan_channel, _, _) = agent.radios[i].get_current_channel()
                if cur_chan_channel != expected_channels[i]:
                    self.fail("Radio {} channel "
                              "switched to {} instead of {}".format(i,
                                                                    cur_chan_channel,
                                                                    expected_channels[i]))

            oper_channel_reports = self.check_cmdu_type("operating channel report",
                                                        self.ieee1905['eMessageType']
                                                        ['OPERATING_CHANNEL_REPORT_MESSAGE'],
                                                        agent.mac, controller.mac)
            for report in oper_channel_reports:
                for ocr in report.ieee1905_tlvs:
                    if ocr.tlv_type != self.ieee1905['eTlvTypeMap']['TLV_OPERATING_CHANNEL_REPORT']:
                        self.fail("Unexpected TLV in operating channel report: {}".format(ocr))
                        continue
                    if int(ocr.operating_channel_eirp) != tp16dBm:
                        self.fail("Unexpected transmit power {} instead of {} for {}".format(
                            ocr.operating_channel_eirp, payload_transmit_power,
                            ocr.operating_channel_radio_id))
                self.check_cmdu_type_single("ACK",
                                            self.ieee1905['eMessageType']['ACK_MESSAGE'],
                                            controller.mac, agent.mac,
                                            report.ieee1905_mid)

            self.checkpoint()
