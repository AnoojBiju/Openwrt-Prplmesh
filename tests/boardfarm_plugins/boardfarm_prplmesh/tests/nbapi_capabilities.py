# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021-2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug
from typing import List
import sniffer

import time


class NbapiCapabilities(PrplMeshBaseTest):
    '''
       Test for NBAPI Device.WiFi.DataElements.Network.Device.Radio.Capabilities object.
       Object describes the Wi-Fi capabilities of the radio.
    '''

    def assertEqualInt(self, name: str, actual: int, expected: str):
        assert int(actual) == int(expected, 0),\
            f"Wrong value for {name}: {int(actual)} expected {int(expected, 0)}"

    def check_op_class(self, supported_op_classes: List[sniffer.TlvStruct],
                       nbapi_op_class_path: str, controller):
        class_nbapi = controller.nbapi_get_parameter(nbapi_op_class_path, "Class")
        max_tx_power_nbapi = controller.nbapi_get_parameter(nbapi_op_class_path, "MaxTxPower")
        non_op_ch_count_nbapi = controller.nbapi_get_parameter(nbapi_op_class_path,
                                                               "NumberOfNonOperChan")

        matching_op_class = [
            op_class for op_class in supported_op_classes if int(op_class.op_class) == class_nbapi
        ]

        assert len(matching_op_class) == 1, f"Wrong NBAPI operating class [{class_nbapi}]."
        op_class = matching_op_class[0]
        self.assertEqualInt("MaxTxPower", max_tx_power_nbapi, op_class.max_power)
        self.assertEqualInt("NumberOfNonOperChan", non_op_ch_count_nbapi, op_class.non_op_channels)
        if non_op_ch_count_nbapi != 0:
            non_op_channels_nbapi = controller.nbapi_get_list_instances(nbapi_op_class_path +
                                                                        ".NonOperable")
            for non_op_channel_nbapi in non_op_channels_nbapi:
                channel = controller.nbapi_get_parameter(non_op_channel_nbapi, "NonOpChannelNumber")

                non_op_channels = [
                    o for o in op_class.non_operating_channel if str(channel) in vars(o).values()
                ]

                assert len(non_op_channels) == 1, f"Non-operable channel {channel} was not found."
        supported_op_classes.remove(op_class)

    def runTest(self):
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        # Send AP capability query as we need TLVs from returning response.
        debug("Send AP capability query to agent")
        mid = controller.dev_send_1905(agent.mac,
                                       self.ieee1905['eMessageType']['AP_CAPABILITY_QUERY_MESSAGE'])
        time.sleep(1)

        debug("Confirming AP capability query has been received on agent")
        self.check_log(agent.radios[0], "AP_CAPABILITY_QUERY_MESSAGE")
        debug("Confirming AP capability report has been received on controller")
        self.check_log(controller, "AP_CAPABILITY_REPORT_MESSAGE")
        ap_cap_report = self.check_cmdu_type(
            "AP_CAPABILITY_REPORT_MESSAGE",
            self.ieee1905['eMessageType']['AP_CAPABILITY_REPORT_MESSAGE'], agent.mac,
            controller.mac, mid)

        topology = self.get_topology()
        repeater = topology[agent.mac]
        for ap_cap_report in ap_cap_report:
            for tlv in ap_cap_report.ieee1905_tlvs:
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_AP_RADIO_BASIC_CAPABILITIES']:
                    radio = repeater.radios[tlv.ap_radio_identifier]
                    op_classes_nbapi = controller.nbapi_get_list_instances(
                        radio.path + ".Capabilities.OperatingClasses")
                    for op_class_nbapi in op_classes_nbapi:
                        self.check_op_class(tlv.supported_operating_classes, op_class_nbapi,
                                            controller)
                    assert not tlv.supported_operating_classes, \
                        "Not all operating classes was reported in data model."
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_AP_HT_CAPABILITIES']:
                    radio = repeater.radios[tlv.ap_ht_radio_id]
                    ht_caps = controller.nbapi_get(radio.path + ".Capabilities.HTCapabilities")
                    self.assertEqualInt("MaxNumberOfRxSpatialStreams",
                                        ht_caps['MaxNumberOfRxSpatialStreams'] - 1,
                                        tlv.ap_ht_caps_tree['ieee1905.ap_ht.max_rx_streams'])
                    self.assertEqualInt("MaxNumberOfTxSpatialStreams",
                                        ht_caps['MaxNumberOfTxSpatialStreams'] - 1,
                                        tlv.ap_ht_caps_tree['ieee1905.ap_ht.max_tx_streams'])
                    self.assertEqualInt("HTShortGI20", ht_caps['HTShortGI20'],
                                        tlv.ap_ht_caps_tree['ieee1905.ap_ht.short_gi_20mhz'])
                    self.assertEqualInt("HTShortGI40", ht_caps['HTShortGI40'],
                                        tlv.ap_ht_caps_tree['ieee1905.ap_ht.short_gi_40mhz'])
                    self.assertEqualInt("HT40", ht_caps['HT40'],
                                        tlv.ap_ht_caps_tree['ieee1905.ap_ht.ht_support_40mhz'])
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_AP_VHT_CAPABILITIES']:
                    radio = repeater.radios[tlv.ap_vht_radio_id]
                    vht_caps = controller.nbapi_get(radio.path + ".Capabilities.VHTCapabilities")
                    self.assertEqualInt("MaxNumberOfRxSpatialStreams",
                                        vht_caps['MaxNumberOfRxSpatialStreams'] - 1,
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.max_rx_streams'])
                    self.assertEqualInt("MaxNumberOfTxSpatialStreams",
                                        vht_caps['MaxNumberOfTxSpatialStreams'] - 1,
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.max_tx_streams'])
                    self.assertEqualInt("VHTShortGI80", vht_caps['VHTShortGI80'],
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.short_gi_80mhz'])
                    self.assertEqualInt("VHTShortGI160", vht_caps['VHTShortGI160'],
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.short_gi_160mhz'])
                    self.assertEqualInt("VHT8080", vht_caps['VHT8080'],
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.vht_80plus_mhz'])
                    self.assertEqualInt("VHT160", vht_caps['VHT160'],
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.vht_160mhz'])
                    self.assertEqualInt("SUBeamformer", vht_caps['SUBeamformer'],
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.su_beamformer'])
                    self.assertEqualInt("MUBeamformer", vht_caps['MUBeamformer'],
                                        tlv.ap_vht_caps_tree['ieee1905.ap_vht.mu_beamformer'])
                    self.assertEqualInt("MCSNSSTxSet", vht_caps['MCSNSSTxSet'],
                                        tlv.vht_supported_tx_mcs)
                    self.assertEqualInt("MCSNSSRxSet", vht_caps['MCSNSSRxSet'],
                                        tlv.vht_supported_rx_mcs)
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_AP_WIFI_6_CAPABILITIES']:
                    radio = repeater.radios[tlv.ap_wifi_6_capability_radio_id]

                    # Determine the role type based on agent_role_first_bit
                    agent_role_first_bit = tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.agent_role'] & 0x01
                    
                    if agent_role_first_bit == 0x0:
                        role_path = ".Capabilities.WiFi6APRole"
                    else:
                        role_path = ".Capabilities.WiFi6bSTARole"
                    
                    wifi6_caps = controller.nbapi_get(radio.path + role_path)

                    self.assertEqualInt("HE160", wifi6_caps['HE160'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.he_160_mhz'])
                    self.assertEqualInt("HE8080", wifi6_caps['HE8080'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.he_80plus_mhz'])
                    self.assertEqualInt("SUBeamformer", wifi6_caps['SUBeamformer'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.su_beamformer'])
                    self.assertEqualInt("MUBeamformer", wifi6_caps['MUBeamformer'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.mu_beamformer'])
                    self.assertEqualInt("ULMUMIMO", wifi6_caps['ULMUMIMO'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.ul_mu_mimo'])
                    self.assertEqualInt("ULOFDMA", wifi6_caps['ULOFDMA'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.he_ul_ofdma'])
                    self.assertEqualInt("DLOFDMA", wifi6_caps['DLOFDMA'],
                                    tlv.ap_wifi6_caps_tree['ieee1905.ap_wifi6.he_dl_ofdma'])

                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_PROFILE2_CAC_CAPABILITIES']:
                    debug("Checking Profile-2 CAC Capabilities TLV")
                    # TODO: Check Profile-2 CAC Capabilities TLV and related DM objects (PPM-2289).
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_CHANNEL_SCAN_CAPABILITIES']:
                    debug("Checking Profile-2 Scan Capabilities TLV")
                    # TODO: Check Profile-2 Scan Capabilities TLV and related DM objects (PPM-2293).
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap'][
                        'TLV_PROFILE2_AP_RADIO_ADVANCED_CAPABILITIES']:
                    debug("Checking AP Radio Advanced Capabilities TLV")
                    # TODO: Check  AP Radio Advanced Capabilities and related DM objects (PPM-2345).
                if tlv.tlv_type == self.ieee1905['eTlvTypeMap']['TLV_DEVICE_INVENTORY']:
                    debug("Checking Profile-3 Device Inventory TLV")
                    # TODO: Check Profile-3 Device Inventory TLV and related DM objects (PPM-2333).
