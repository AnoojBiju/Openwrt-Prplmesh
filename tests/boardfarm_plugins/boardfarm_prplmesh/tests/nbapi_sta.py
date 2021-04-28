
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from opts import debug

import time
from datetime import datetime, timedelta
import dateutil.parser
import pytz
import re


class NbapiSta(PrplMeshBaseTest):
    '''
    This test checks various parameters of NBAPI sta object.
    Path to this object: Controller.Network.Device.Radio.BSS.STA
    '''

    def runTest(self):
        try:
            agent = self.dev.DUT.agent_entity
            sta1 = self.dev.wifi
            controller = self.dev.lan.controller_entity
            vap1 = agent.radios[0].vaps[0]
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)
        self.configure_ssids_clear()
        self.configure_ssid("ImSSID24G", "Fronthaul", {"Band2_4G": True})
        self.configure_ssid("ImSSID5GH", "Fronthaul", {"Band5GH": True})
        controller.nbapi_command("Controller.Network", "AccessPointCommit")

        time.sleep(3)
        sta1.wifi_connect(vap1)

        agent.radios[1].send_bwl_event(
            "DATA STA-UPDATE-STATS {} rssi=-38,-39,-40,-41 snr=38,39,40,41 "
            "uplink=1000 downlink=800".format(sta1.mac))

        print("\nNetwork topology after settings:")
        topology = self.get_topology()
        for device in topology.values():
            print(device)

        time_before_query = datetime.now()
        time_before_query = pytz.utc.localize(time_before_query)

        debug('Send AP Metrics Query Message')
        mid1 = controller.dev_send_1905(agent.mac, 0x800B,
                                        tlv(0x93, 0x0007, "0x01 {%s}" % (vap1.bssid)))
        debug("Send Associated STA Link Metrics Query message")
        controller.ucc_socket.dev_send_1905(agent.mac, 0x800D, tlv(0x95, 0x0006, sta1.mac))
        time.sleep(2)

        ap_metrics_resp = self.check_cmdu_type_single("AP metrics response", 0x800C, agent.mac,
                                                      controller.mac, mid1)

        debug("Check AP metrics response has STA traffic stats")
        traffic_stats = self.check_cmdu_has_tlv_single(ap_metrics_resp, 0xa2)
        debug("Check AP metrics response has STA Link Metrics")
        sta_link_metrics = self.check_cmdu_has_tlv_single(ap_metrics_resp, 0x96)

        for radio in topology[agent.mac].radios.values():
            for bss in radio.vaps.values():
                for sta in bss.clients.values():
                    sta_mac = controller.nbapi_get_parameter(sta.path, "MACAddress")
                    time_stamp = controller.nbapi_get_parameter(sta.path, "TimeStamp")
                    signal_strength = controller.nbapi_get_parameter(sta.path, "SignalStrength")
                    ipv4_address = controller.nbapi_get_parameter(sta.path, "IPV4Address")
                    ipv6_address = controller.nbapi_get_parameter(sta.path, "IPV6Address")
                    hostname = controller.nbapi_get_parameter(sta.path, "Hostname")

                    assert sta_mac == sta1.mac, f"Wrong sta mac {sta_mac} expect {sta1.mac}"
                    self.assertEqual(sta.path, "BytesSent",
                                     traffic_stats.assoc_sta_traffic_stats_bytes_sent)
                    self.assertEqual(sta.path, "BytesReceived",
                                     traffic_stats.assoc_sta_traffic_stats_bytes_rcvd)
                    self.assertEqual(sta.path, "PacketsSent",
                                     traffic_stats.assoc_sta_traffic_stats_packets_sent)
                    self.assertEqual(sta.path, "PacketsReceived",
                                     traffic_stats.assoc_sta_traffic_stats_packets_rcvd)
                    self.assertEqual(sta.path, "ErrorsReceived",
                                     traffic_stats.assoc_sta_traffic_stats_rx_packet_errs)
                    self.assertEqual(sta.path, "ErrorsSent",
                                     traffic_stats.assoc_sta_traffic_stats_tx_pkt_errs)
                    self.assertEqual(sta.path, "RetransCount",
                                     traffic_stats.assoc_sta_traffic_stats_retrans_count)
                    self.assertEqual(sta.path, "EstMACDataRateDownlink",
                                     sta_link_metrics.bss[0].down_rate)
                    self.assertEqual(sta.path, "EstMACDataRateUplink",
                                     sta_link_metrics.bss[0].up_rate)
                    assert signal_strength == sta_link_metrics.bss[0].rssi, \
                        f"Wrong value for SignalStrength {signal_strength}"
                    assert sta_link_metrics.bss[0].bssid == bss.bssid, \
                        f"Wrong BSSID [{bss.bssid}] specified for sta {sta.mac}"
                    assert time_stamp != 0, "Value for TimeStamp is not specified."

                    self.get_nbapi_ht_capabilities(sta.path)
                    self.get_nbapi_vht_capabilities(sta.path)

                    time_sta = dateutil.parser.isoparse(time_stamp)
                    # TO DO: PPM-1230
                    if time_sta <= time_before_query:
                        debug('Fail. Sta time group was collected earlier '
                              'than AP Metrics Query was sent.')
                    if time_before_query + timedelta(seconds=10) <= time_sta:
                        self.fail('Fail. Sta time group was collected '
                                  'more than 10s after AP Metrics Query was send.')
                    print(
                        f'Sta group was collected at: [{time_sta}], '
                        f'time before query: {time_before_query}')

                    check_time_format = re.match(
                        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+(Z|[-+]\d{2}:\d{2})',
                        time_stamp)
                    if check_time_format is None:
                        self.fail(f'Fail. NBAPI time stamp has unncorrect format: {time_stamp}')
                    # TO DO: PPM-535, PPM-534 Uncomment after issues are complete.
                    # assert ipv6_address != "0" or ipv4_address != "0",\
                    #     "Value for ipv4 and for ipv6 address not specified."
                    # assert hostname != 0, "Missing value for ipv4 address."
                    (ipv4_address)
                    (ipv6_address)
                    (hostname)
        sta1.wifi_disconnect(vap1)
