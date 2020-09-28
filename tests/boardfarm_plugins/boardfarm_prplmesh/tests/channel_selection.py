###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time
from typing import Callable, Union, Any, NoReturn

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from opts import debug, err, message, opts, status


class ChannelSelection(PrplMeshBaseTest):

    def runTest(self):

        def check_single_channel_response(self, resp_code) -> None:
            cs_resp = self.check_cmdu_type_single("channel selection response", 0x8007, agent.mac,
                                                  controller.mac, cs_req_mid)  # noqa E501
            if cs_resp:
                cs_resp_tlvs = self.check_cmdu_has_tlvs(cs_resp, 0x8e)
                for cs_resp_tlv in cs_resp_tlvs:
                    if cs_resp_tlv.channel_select_radio_id not in (agent.radios[0].mac,
                                                                   agent.radios[1].mac):
                        if int(cs_resp_tlv.channel_select_response_code, 16) != resp_code:
                            self.fail("Unexpected radio ID {}\n"
                                      "Channel selection unexpected response code {}".format(
                                cs_resp_tlv.channel_select_radio_id,  # noqa E501
                                cs_resp_tlv.channel_select_response_code
                            ))
                        self.fail("Unexpected radio ID {}".format(
                            cs_resp_tlv.channel_select_radio_id))

        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        orig_chan_0 = agent.radios[0].get_current_channel()
        orig_chan_1 = agent.radios[1].get_current_channel()
        debug("Starting channel wlan0: {}, wlan2: {}".format(orig_chan_0, orig_chan_1))

        debug("Send channel preference query")
        ch_pref_query_mid = controller.ucc_socket.dev_send_1905(agent.mac, 0x8004)
        time.sleep(3)
        debug("Confirming channel preference query has been received on agent")

        # TODO should be a single response (currently two are sent)
        self.check_cmdu_type("channel preference response", 0x8005, agent.mac,
                             controller.mac, ch_pref_query_mid)

        debug("Send empty channel selection request")
        cs_req_mid = controller.dev_send_1905(agent.mac,
                                              0x8006,
                                              tlv(0x00, 0x0000, "{}"))

        time.sleep(1)

        check_single_channel_response(self, 0x00)

        cur_chan_0 = agent.radios[0].get_current_channel()
        cur_chan_1 = agent.radios[1].get_current_channel()

        if cur_chan_0 != orig_chan_0:
            self.fail("Radio 0 channel switched to {}".format(cur_chan_0))
        if cur_chan_1 != orig_chan_1:
            self.fail("Radio 1 channel switched to {}".format(cur_chan_1))

        oper_channel_reports = self.check_cmdu_type("operating channel report", 0x8008,
                                                    agent.mac, controller.mac)
        for report in oper_channel_reports:
            self.check_cmdu_type_single("ACK", 0x8000, controller.mac, agent.mac,
                                        report.ieee1905_mid)

        self.checkpoint()

        tp20dBm = 0x14
        tp21dBm = 0x15

        for payload_transmit_power in (tp20dBm, tp21dBm):
            debug("Send empty channel selection request with changing tx_power_limit")
            cs_req_mid = controller.dev_send_1905(
                agent.mac,
                0x8006,
                tlv(0x8D, 0x0007, '{} 0x{:02x}'.format(agent.radios[0].mac,
                                                       payload_transmit_power)),
                tlv(0x8D, 0x0007, '{} 0x{:02x}'.format(agent.radios[1].mac,
                                                       payload_transmit_power))
            )
            time.sleep(1)

            self.check_log(agent.radios[0],
                           "tlvTransmitPowerLimit {}".format(payload_transmit_power))
            self.check_log(agent.radios[1],
                           "tlvTransmitPowerLimit {}".format(payload_transmit_power))

            # TODO should be a single response (currently two are sent)
            self.check_cmdu_type("channel selection response", 0x8007, agent.mac,
                                 controller.mac, cs_req_mid)

            cur_chan_0 = agent.radios[0].get_current_channel()
            cur_chan_1 = agent.radios[1].get_current_channel()
            if cur_chan_0 != orig_chan_0:
                self.fail("Radio 0 channel switched to {}".format(cur_chan_0))
            if cur_chan_1 != orig_chan_1:
                self.fail("Radio 1 channel switched to {}".format(cur_chan_1))

            oper_channel_reports = self.check_cmdu_type("operating channel report", 0x8008,
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
                self.check_cmdu_type_single("ACK", 0x8000, controller.mac, agent.mac,
                                            report.ieee1905_mid)

            self.checkpoint()

        debug("Send invalid channel selection request to radio 0")
        cs_req_mid = controller.dev_send_1905(
            agent.mac, 0x8006,
            # Single operating class with a single channel that doesn't exist in it.
            tlv(0x8B, 0x000B, agent.mac + ' 0x01 {0x52 {0x01 {0x01}} 0x00}'))
        time.sleep(1)

        check_single_channel_response(self, 0x02)

        self.checkpoint()

        # payload_wlan0 - request for change channel on 6
        payload_wlan0 = (
            "0x14 "
            "{0x51 {0x0C {0x01 0x02 0x03 0x04 0x05 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D} 0x00}} "
            "{0x52 {0x00 0x00}} "
            "{0x53 {0x08 {0x01 0x02 0x03 0x04 0x05 0x07 0x08 0x09} 0x00}} "
            "{0x54 {0x08 {0x05 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D} 0x00}} "
            "{0x73 {0x00 0x00}} "
            "{0x74 {0x00 0x00}} "
            "{0x75 {0x00 0x00}} "
            "{0x76 {0x00 0x00}} "
            "{0x77 {0x00 0x00}} "
            "{0x78 {0x00 0x00}} "
            "{0x79 {0x00 0x00}} "
            "{0x7A {0x00 0x00}} "
            "{0x7B {0x00 0x00}} "
            "{0x7C {0x00 0x00}} "
            "{0x7D {0x00 0x00}} "
            "{0x7E {0x00 0x00}} "
            "{0x7F {0x00 0x00}} "
            "{0x80 {0x00 0x00}} "
            "{0x81 {0x00 0x00}} "
            "{0x82 {0x00 0x00}} "
        )

        # payload_wlan2  - request for change channel on 36
        payload_wlan2 = (
            "0x14 "
            "{0x51 {0x00 0x00}} "
            "{0x52 {0x00 0x00}} "
            "{0x53 {0x00 0x00}} "
            "{0x54 {0x00 0x00}} "
            "{0x73 0x03 {0x28 0x2C 0x30} 0x00} "
            "{0x74 0x01 {0x2C} 0x00} "
            "{0x75 {0x00 0x00}} "
            "{0x76 {0x00 0x00}} "
            "{0x77 {0x00 0x00}} "
            "{0x78 {0x00 0x00}} "
            "{0x79 {0x00 0x00}} "
            "{0x7A {0x00 0x00}} "
            "{0x7B {0x00 0x00}} "
            "{0x7C {0x00 0x00}} "
            "{0x7D {0x00 0x00}} "
            "{0x7E {0x00 0x00}} "
            "{0x7F {0x00 0x00}} "
            "{0x80 0x05 {0x3A 0x6A 0x7A 0x8A 0x9B} 0x00} "
            "{0x81 {0x00 0x00}} "
            "{0x82 {0x00 0x00}}"
        )

        """
        Step 1: Trigger channel selection to channel 6 and 36. Check that
                operating channel report was sent.

        Step 2: Trigger channel selection to channel 6 and 36 again - check that
                operating channel report is sent again. This is to catch bugs
                when we don't send channel report when there is no need to
                switch channel
        """
        for i in range(1, 3):
            debug("Send channel selection request, step {}".format(i))
            cs_req_mid = controller.dev_send_1905(
                agent.mac,
                0x8006,
                tlv(0x8B, 0x005F, '{} {}'.format(agent.radios[0].mac, payload_wlan0)),
                tlv(0x8D, 0x0007, '{} 0x{:2x}'.format(agent.radios[0].mac, tp20dBm)),
                tlv(0x8B, 0x004C, '{} {}'.format(agent.radios[1].mac, payload_wlan2)),
                tlv(0x8D, 0x0007, '{} 0x{:2x}'.format(agent.radios[1].mac, tp20dBm))
            )
            time.sleep(1)

            debug("Confirming tlvTransmitPowerLimit has been received with correct value on agent,"
                  " step {}".format(i))

            self.check_log(agent.radios[0], "tlvTransmitPowerLimit {}".format(tp20dBm))
            self.check_log(agent.radios[1], "tlvTransmitPowerLimit {}".format(tp20dBm))

            check_single_channel_response(self, 0x00)

            # payload_wlan0 and payload_wlan1 forced to channel 6 resp. 36, check that this happened
            (cur_chan_channel_0, _, _) = agent.radios[0].get_current_channel()
            (cur_chan_channel_1, _, _) = agent.radios[1].get_current_channel()
            if cur_chan_channel_0 != 6:
                self.fail("Radio 0 channel switched to {} instead of 6".format(cur_chan_channel_0))
            if cur_chan_channel_1 != 36:
                self.fail("Radio 1 channel switched to {} instead of 36".format(cur_chan_channel_1))

            oper_channel_reports = self.check_cmdu_type("operating channel report", 0x8008,
                                                        agent.mac, controller.mac)
            for report in oper_channel_reports:
                for ocr in report.ieee1905_tlvs:
                    if ocr.tlv_type != 0x8F:
                        self.fail("Unexpected TLV in operating channel report: {}".format(ocr))
                        continue
                    if int(ocr.operating_channel_eirp) != tp20dBm:
                        self.fail("Unexpected transmit power {} instead of {} for {}".format(
                            ocr.operating_channel_eirp, payload_transmit_power,
                            ocr.operating_channel_radio_id))
                self.check_cmdu_type_single("ACK", 0x8000, controller.mac, agent.mac,
                                            report.ieee1905_mid)

            self.checkpoint()

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
