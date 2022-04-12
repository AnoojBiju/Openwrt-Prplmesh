
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug
import time


class NbapiRadioBackhaulSta(PrplMeshBaseTest):
    '''
       Test for NBAPI Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta object.
       Object stores MACAddress of the Backhaul Station (bSTA) on given radio.
       It also checks Backhaul STA Radio Capabilities TLV.
    '''

    def runTest(self):
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        debug("Send Backhaul STA capability query to agent")
        mid = controller.dev_send_1905(
            agent.mac, self.ieee1905['eMessageType']['BACKHAUL_STA_CAPABILITY_QUERY_MESSAGE'])

        topology = self.get_topology()
        radios = topology[agent.mac].radios.values()

        debug("Confirming Backhaul STA Capability Query has been received on agent")
        self.check_log(
            agent,
            r"BACKHAUL_STA_CAPABILITY_QUERY_MESSAGE, mid=0x{:02x}".format(mid),
            timeout=1)

        debug("Confirming Backhaul STA Capability Query has been received on controller")
        self.check_log(controller,
                       r"BACKHAUL_STA_CAPABILITY_REPORT_MESSAGE, mid=0x{:02x}".format(mid))

        # Waiting for CMDU
        time.sleep(0.5)

        backhaul_sta_cap_report = self.check_cmdu_type_single(
            "Backhaul STA Capability Report",
            self.ieee1905['eMessageType']['BACKHAUL_STA_CAPABILITY_REPORT_MESSAGE'],
            agent.mac,
            controller.mac,
            mid)
        backhaul_sta_radio_caps_tlvs = self.check_cmdu_has_tlvs(
            backhaul_sta_cap_report, self.ieee1905['eTlvTypeMap']
            ['TLV_BACKHAUL_STA_RADIO_CAPABILITIES'])

        debug("Checking TLV contents")
        for tlv, index in zip(backhaul_sta_radio_caps_tlvs, range(len(radios))):

            assert tlv.tlv_length, "tlv_length of Backhaul STA Radio Capabilities TLV is empty!"
            tlv_ruid = tlv.backhaul_sta_radio_capabilities_radio_id
            tlv_sta_mac_included = int(
                tlv.backhaul_sta_radio_capabilities_flags_tree
                ['ieee1905.backhaul_sta_radio_capabilities.mac_address_included'])

            assert tlv_ruid == agent.radios[index].mac, \
                f"Wrong ruid: {tlv_ruid}, expected {agent.radios[index].mac}"
            debug(f'TLV Radio UID: {tlv_ruid}')

            if tlv_sta_mac_included:
                tlv_backhaul_sta_mac = tlv.backhaul_sta_radio_capabilities_backhaul_sta_mac_address

                assert tlv_backhaul_sta_mac == '00:00:00:00:00:00', \
                    "Received TLV Backhaul STA MAC should be zeroed out"

                """
                TODO: Сheck the Backhaul STA MAC value from TLV and NBAPI by comparing it with
                dummy value.
                Now, MAC parameter includes in TLV as zeroed value for wired mode.
                PPM-2016.

                backhaul_mac = agent.radios[index].backhaul_sta_list[0].mac
                assert tlv_backhaul_sta_mac == backhaul_mac, \
                    f"Wrong TLV Backhaul STA MAC: {tlv_backhaul_sta_mac}, \
                        expected {backhaul_mac}"
                """

                debug("Checking NBAPI BackhaulSta object")
                nbapi_backhaul_sta_mac = controller.nbapi_get_parameter(
                    topology[agent.mac].radios[tlv_ruid].path + ".BackhaulSta", "MACAddress")

                assert nbapi_backhaul_sta_mac == '00:00:00:00:00:00', \
                    "Received NBAPI Backhaul STA MAC should be zeroed out"

                """
                assert nbapi_backhaul_sta_mac == backhaul_mac, \
                    f"Wrong NBAPI Backhaul STA MAC: {nbapi_backhaul_sta_mac}, \
                   expected {backhaul_mac}"
                """
                debug(f'BackhaulSta.MACAddress: {nbapi_backhaul_sta_mac}')
            else:
                assert False, "Backhaul STA MAC address is not included in TLV!"
