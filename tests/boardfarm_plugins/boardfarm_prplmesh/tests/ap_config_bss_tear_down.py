# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from capi import tlv

import time


class ApConfigBSSTeardown(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        # Configure the controller and send renew
        controller.cmd_reply("DEV_RESET_DEFAULT")
        controller.cmd_reply(
            "DEV_SET_CONFIG,bss_info1,"
            "{} 8x Multi-AP-24G-3 0x0020 0x0008 maprocks1 0 1".format(agent.mac))
        controller.dev_send_1905(agent.mac, 0x000A,
                                 tlv(0x01, 0x0006, "{" + controller.mac + "}"),
                                 tlv(0x0F, 0x0001, "{0x00}"),
                                 tlv(0x10, 0x0001, "{0x00}"))

        # Wait a bit for the renew to complete
        time.sleep(3)

        self.check_log(agent.radios[0],
                       r"Received credentials for ssid: Multi-AP-24G-3 .*"
                       r"fronthaul: true backhaul: false")
        self.check_log(agent.radios[1], r".* tear down radio")
        conn_map = controller.get_conn_map()
        repeater1 = conn_map[agent.mac]
        repeater1_wlan0 = repeater1.radios[agent.radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid not in (b'Multi-AP-24G-3', b'N/A'):
                self.fail('Wrong SSID: {vap.ssid} instead of Multi-AP-24G-3'.format(vap=vap))
        repeater1_wlan2 = repeater1.radios[agent.radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

        # SSIDs have been removed for the CTT Agent1's front radio
        controller.cmd_reply(
            "DEV_SET_CONFIG,bss_info1,{} 8x".format(agent.mac))
        # Send renew message
        controller.dev_send_1905(agent.mac, 0x000A,
                                 tlv(0x01, 0x0006, "{" + controller.mac + "}"),
                                 tlv(0x0F, 0x0001, "{0x00}"),
                                 tlv(0x10, 0x0001, "{0x00}"))

        time.sleep(3)
        self.check_log(agent.radios[0], r".* tear down radio")
        conn_map = controller.get_conn_map()
        repeater1 = conn_map[agent.mac]
        repeater1_wlan0 = repeater1.radios[agent.radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))
        repeater1_wlan2 = repeater1.radios[agent.radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

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
