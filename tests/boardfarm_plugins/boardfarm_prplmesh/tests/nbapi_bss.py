
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug
from capi import tlv

import time
from datetime import datetime, timedelta
import dateutil.parser
import pytz
import re


class NbapiBSS(PrplMeshBaseTest):
    '''
    Test for NBAPI BSS object.
    '''

    def assertEqual(self, name: str, actual: int, expected: str):
        print(f'Actual: {actual} expected: {expected}')
        assert actual == int(expected), f"Wrong value for {name}: {actual} expected {expected}"

    def runTest(self):
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
            vap = agent.radios[0].vaps[0]
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)
        time_bss_appear = datetime.now()
        time_bss_appear = pytz.utc.localize(time_bss_appear)
        self.configure_ssids(["NbapiBSS"])

        topology = self.get_topology()
        for device in topology.values():
            print(device)

        debug("Send AP Metrics Query message to agent 1")
        self.send_and_check_policy_config_metric_reporting(controller, agent, True, False)
        mid = controller.dev_send_1905(agent.mac, 0x800B,
                                       tlv(0x93, 0x0007, "0x01 {%s}" % (vap.bssid)))
        time.sleep(1)
        ap_metric_resp = self.check_cmdu_type_single("AP Metrics Response", 0x800C, agent.mac,
                                                     controller.mac, mid)
        ap_metrics = self.check_cmdu_has_tlv_single(ap_metric_resp, 0x94)

        # TO DO: All comments should be uncommented after PPM-1170
        # ap_extended_metrics = self.check_cmdu_has_tlv_single(ap_metric_resp, 0xC7)

        repeater = topology[agent.mac]
        radio = repeater.radios[agent.radios[0].mac]
        for bss in radio.vaps.values():
            time_stamp = controller.nbapi_get_parameter(bss.path, "TimeStamp")
            # uinicast_bytes_sent = controller.nbapi_get_parameter(bss.path, "UnicastBytesSent")
            # unicast_bytes_received = controller.nbapi_get_parameter(
            #     bss.path, "UnicastBytesReceived")
            # multicast_bytes_sent = controller.nbapi_get_parameter(bss.path, "MulticastBytesSent")
            # multicast_bytes_received = controller.nbapi_get_parameter(
            #     bss.path, "MulticastBytesReceived")
            # broadcast_bytes_sent = controller.nbapi_get_parameter(bss.path, "BroadcastBytesSent")
            # broadcast_bytes_received = controller.nbapi_get_parameter(
            #     bss.path, "BroadcastBytesReceived")
            est_service_params_be = controller.nbapi_get_parameter(
                bss.path, "EstServiceParametersBE")
            est_service_params_bk = controller.nbapi_get_parameter(
                bss.path, "EstServiceParametersBK")
            est_service_params_vi = controller.nbapi_get_parameter(
                bss.path, "EstServiceParametersVI")
            est_service_params_vo = controller.nbapi_get_parameter(
                bss.path, "EstServiceParametersVO")

            time_nbapi = dateutil.parser.isoparse(time_stamp)
            assert time_nbapi - timedelta(seconds=3) <= time_bss_appear and\
                time_bss_appear <= time_nbapi + timedelta(seconds=3), \
                f"TimeStamp out of timeframe. Expect: +-3s {time_bss_appear}, actual: {time_nbapi}."

            expected_time_format = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+(Z|[-+]\d{2}:\d{2})'

            if re.match(expected_time_format, time_stamp) is None:
                self.fail(f'Fail. Network time stamp has incorrect format: {time_stamp}')

            # self.assertEqual("UnicastBytesSent", uinicast_bytes_sent,
            #                  ap_extended_metrics.unicast_bytes_sent)
            # self.assertEqual("UnicastBytesReceived", unicast_bytes_received,
            #                  ap_extended_metrics.unicast_bytes_received)
            # self.assertEqual("MulticastBytesSent", multicast_bytes_sent,
            #                  ap_extended_metrics.multicast_bytes_sent)
            # self.assertEqual("MulticastBytesReceived", multicast_bytes_received,
            #                  ap_extended_metrics.multicast_bytes_received)
            # self.assertEqual("BroadcastBytesSent", broadcast_bytes_sent,
            #                  ap_extended_metrics.Broadcast_bytes_sent)
            # self.assertEqual("BroadcastBytesReceived", broadcast_bytes_received,
            #                  ap_extended_metrics.broadcast_bytes_received)

            be = getattr(ap_metrics, 'ap_metrics_est_param_be', 0)
            bk = getattr(ap_metrics, 'ap_metrics_est_param_bk', 0)
            vo = getattr(ap_metrics, 'ap_metrics_est_param_vo', 0)
            vi = getattr(ap_metrics, 'ap_metrics_est_param_vi', 0)

            be = int(be.replace(':', ''), 16)
            # bk = int(bk.replace(':', ''), 16)
            # vo = int(vo.replace(':', ''), 16)
            # vi = int(vi.replace(':', ''), 16)

            assert bin(be) == bin(est_service_params_be), \
                f"Wrong value for EstServiceParametersBE [{est_service_params_be}] expect [{be}]"
            assert bin(bk) == bin(est_service_params_bk), \
                f"Wrong value for EstServiceParametersBK [{est_service_params_bk}] expect [{bk}]"
            assert bin(vo) == bin(est_service_params_vo), \
                f"Wrong value for EstServiceParametersVO [{est_service_params_vo}] expect [{vo}]"
            assert bin(vi) == bin(est_service_params_vi), \
                f"Wrong value for EstServiceParametersVI [{est_service_params_vi}] expect [{vi}]"
