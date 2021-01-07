# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv
from opts import debug
import time


class BeaconReportQuery(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            sta = self.dev.wifi
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        debug("Connect dummy STA (" + sta.mac + ") to wlan0")
        agent.radios[0].vaps[0].associate(sta)

        # send beacon query request
        # (please take a look at https://github.com/prplfoundation/prplMesh/issues/1272)
        debug("Sending beacon report query to repeater:")
        request = '{mac} '.format(mac=sta.mac)
        request += '0x73 0xFF 0xFFFFFFFFFFFF 0x02 0x00 0x01 0x02 0x73 0x24 0x30 0x00'

        debug(request)
        mid = controller.dev_send_1905(agent.mac, 0x8011,
                                       tlv(0x99, 0x0016,
                                           "{" + request + "}"))

        time.sleep(3)
        self.check_cmdu_type("ACK", 0x8000, agent.mac, controller.mac, mid)

        # this line is printed in the monitor log - however currently there is no way to test it -
        # self.check_log(env.agents[0].radios[0].???,
        #                r"inserting 1 RRM_EVENT_BEACON_REP_RXED event(s) to the pending list")
        agent.radios[0].vaps[0].disassociate(sta)

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
