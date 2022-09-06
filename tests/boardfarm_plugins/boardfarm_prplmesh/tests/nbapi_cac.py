###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug


class NbapiCAC(PrplMeshBaseTest):
    """
    Devices used in test setup:
            AP1 - Agent1 [DUT]
            GW - Controller

    Test for NBAPI Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}. object
    and its sub-objects:
            CACAvailableChannel.{i}.
            CACNonOccupancyChannel.{i}.
            CACActiveChannel.{i}.
    """

    def runTest(self):

        def check_cac_completion_report(self, agent, channel_pref_report) -> None:
            report = self.check_cmdu_has_tlv_single(
                channel_pref_report,
                self.ieee1905['eTlvTypeMap']['TLV_PROFILE2_CAC_COMPLETION_REPORT'])
            assert report.tlv_length, "tlv_length of CAC Completion Report TLV is empty!"

            # Check number of reported radios
            assert int(report.cac_completion_report_number_of_radios) == len(agent.radios)

            for radio in report.radio:
                assert agent.radios.get(radio.radio_id)
                # TODO: Check Completion Status (PPM-2301)
                # assert radio.cac_completion_status == '255'

        def check_cac_channel(tlv_report, dm_ch_path, ch_idx) -> None:
            if "CACAvailableChannel" in dm_ch_path:
                tlv_op_class = tlv_report.available_channels[ch_idx -
                                                             1].available_channel_operating_class
                tlv_ch = tlv_report.available_channels[ch_idx - 1].available_channel_channel
                tlv_duration = tlv_report.available_channels[ch_idx -
                                                             1].available_channel_minutes_since
                dm_duration_name = 'Minutes'
            elif "CACNonOccupancyChannel" in dm_ch_path:
                tlv_op_class = tlv_report.non_occupancy[ch_idx -
                                                        1].non_occupied_channel_operating_class
                tlv_ch = tlv_report.non_occupancy[ch_idx - 1].non_occupied_channel_channel
                tlv_duration = tlv_report.non_occupancy[ch_idx -
                                                        1].non_occupied_channel_second_remaining
                dm_duration_name = 'Seconds'
            elif "CACActiveChannel" in dm_ch_path:
                tlv_op_class = tlv_report.active_cac[ch_idx - 1].active_cac_operating_class
                tlv_ch = tlv_report.active_cac[ch_idx - 1].active_cac_channel
                # Converting duration value
                tmp_duration_value = int(tlv_report.active_cac[ch_idx -
                                                               1].active_cac_seconds_remaining)
                tlv_duration = int.from_bytes(tmp_duration_value.to_bytes(3, 'little'), 'big')
                dm_duration_name = 'Countdown'
            else:
                assert False, f"Wrong DM path '{dm_ch_path}'. Need path to channel object."

            dm_ch_path += "." + str(ch_idx)
            dm_ch = controller.nbapi_get(dm_ch_path)
            assert 0 < int(tlv_op_class) < 255, \
                f"Operational class value must be greater than 0" \
                f" and less than 255, not '{int(tlv_op_class)}'"
            assert int(tlv_op_class) == dm_ch['OpClass'], \
                f"Wrong value '{dm_ch['OpClass']}' for {dm_ch_path}.OpClass," \
                f" expected '{tlv_op_class}'"
            # TODO: Add check for max value of channel number (PPM-2301)
            assert 0 < int(tlv_ch), "Channel value must be greater than 0"
            assert int(tlv_ch) == dm_ch['Channel'], \
                f"Wrong value '{dm_ch['Channel']}' for {dm_ch_path}.Channel," \
                f" expected '{tlv_ch}'"
            # TODO: Add check for min and max values of duration (PPM-2301)
            assert int(tlv_duration) == dm_ch[dm_duration_name], \
                f"Wrong value '{dm_ch[dm_duration_name]}' for {dm_ch_path}.{dm_duration_name}," \
                f" expected '{tlv_duration}'"

        def check_cac_status_report(self, agent, channel_pref_report) -> None:
            report = self.check_cmdu_has_tlv_single(
                channel_pref_report, self.ieee1905['eTlvTypeMap']['TLV_PROFILE2_CAC_STATUS_REPORT'])

            assert report.tlv_length, "tlv_length of CAC Status Report TLV is empty!"

            # Get CACStatus object
            # TODO: Need to get the specified index (PPM-2301)
            dm_cac_status_path = agent.path + ".CACStatus.1"
            dm_cac_status = controller.nbapi_get(dm_cac_status_path)
            for key, value in sorted(dm_cac_status.items()):
                debug("{} : {}".format(key, value))

            debug("Check available channels")
            dm_ch_num = dm_cac_status['CACAvailableChannelNumberOfEntries']
            assert int(report.cac_status_report_available_channel_count) == dm_ch_num, \
                f"Wrong value for {dm_cac_status_path}.CACAvailableChannelNumberOfEntries," \
                f" expected {report.cac_status_report_available_channel_count}"

            if int(report.cac_status_report_available_channel_count) > 0:
                # Check first and last reported channels
                dm_ch_path = dm_cac_status_path + ".CACAvailableChannel"
                check_cac_channel(report, dm_ch_path, 1)
                check_cac_channel(report, dm_ch_path, dm_ch_num)

            debug("Check non-occupancy channels")
            dm_ch_num = dm_cac_status['CACNonOccupancyChannelNumberOfEntries']
            assert int(report.cac_status_report_non_occupied_channel_count) == dm_ch_num, \
                f"Wrong value for {dm_cac_status_path}.CACNonOccupancyChannelNumberOfEntries," \
                f" expected {report.cac_status_report_non_occupied_channel_count}"

            if int(report.cac_status_report_non_occupied_channel_count) > 0:
                # Check first and last reported channels
                dm_ch_path = dm_cac_status_path + ".CACNonOccupancyChannel"
                check_cac_channel(report, dm_ch_path, 1)
                check_cac_channel(report, dm_ch_path, dm_ch_num)

            debug("Check active channels")
            dm_ch_num = dm_cac_status['CACActiveChannelNumberOfEntries']
            assert int(report.cac_status_report_active_cac_channel_count) == dm_ch_num, \
                f"Wrong value for {dm_cac_status_path}.CACActiveChannelNumberOfEntries," \
                f" expected {report.cac_status_report_active_cac_channel_count}"

            if int(report.cac_status_report_active_cac_channel_count) > 0:
                # Check first and last reported channels
                dm_ch_path = dm_cac_status_path + ".CACActiveChannel"
                check_cac_channel(report, dm_ch_path, 1)
                check_cac_channel(report, dm_ch_path, dm_ch_num)

        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        self.configure_ssids(['TestCAC'])

        self.checkpoint()

        topology = self.get_topology()

        orig_chan_0 = agent.radios[0].get_current_channel()
        orig_chan_1 = agent.radios[1].get_current_channel()
        debug("Starting channel wlan0: {}, wlan2: {}".format(orig_chan_0, orig_chan_1))

        debug("Send Channel Preference Query")
        ch_pref_query_mid = controller.dev_send_1905(
            agent.mac, self.ieee1905['eMessageType']['CHANNEL_PREFERENCE_QUERY_MESSAGE'])

        time.sleep(3)

        debug("Confirming Channel Preference Query has been received on agent")
        channel_pref_report = self.check_cmdu_type_single(
            "Channel Preference Report",
            self.ieee1905['eMessageType']['CHANNEL_PREFERENCE_REPORT_MESSAGE'], agent.mac,
            controller.mac, ch_pref_query_mid)

        debug("Check Channel Preference Report has CAC Completion Report TLV")
        check_cac_completion_report(self, topology[agent.mac], channel_pref_report)

        debug("Check Channel Preference Report has CAC Status Report TLV")
        check_cac_status_report(self, topology[agent.mac], channel_pref_report)
        """
        TODO: Reproduce another cases to check non-occupancy/active channels
              and duration parameters (PPM-2301).
              For checking, use check_cac_status_report().
        """
