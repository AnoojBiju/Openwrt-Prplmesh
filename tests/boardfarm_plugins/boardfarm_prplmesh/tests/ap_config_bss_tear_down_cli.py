# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest

import time


class ApConfigBSSTeardownCli(PrplMeshBaseTest):
    """Check SSID is still available after being torn down

            Devices used in test setup:
            AP1 - Agent1 [DUT]
            GW - Controller

    """

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        # Same test as the previous one but using CLI instead of dev_send_1905

        controller.beerocks_cli_command('bml_clear_wifi_credentials {}'.format(agent.mac))
        controller.beerocks_cli_command('bml_set_wifi_credentials {} {} {} {} {}'
                                        .format(agent.mac,
                                                "Boardfarm-Tests-24G-3-cli",
                                                "maprocks1",
                                                "24g",
                                                "fronthaul"))
        controller.beerocks_cli_command('bml_update_wifi_credentials {}'.format(agent.mac))

        # Wait a bit for the renew to complete
        time.sleep(3)

        self.check_log(agent.radios[0],
                       r"Received credentials for ssid: Boardfarm-Tests-24G-3-cli .*"
                       r"fronthaul: true backhaul: false")
        self.check_log(agent.radios[1], r".* tear down radio")
        conn_map = controller.get_conn_map()
        repeater1 = conn_map[agent.mac]
        repeater1_wlan0 = repeater1.radios[agent.radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid not in (b'Boardfarm-Tests-24G-3-cli', b'N/A'):
                self.fail('Wrong SSID: {vap.ssid} instead of Boardfarm-Tests-24G-3-cli'.format
                          (vap=vap))
        repeater1_wlan2 = repeater1.radios[agent.radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

        controller.beerocks_cli_command('bml_clear_wifi_credentials {}'.format(agent.mac))
        controller.beerocks_cli_command('bml_update_wifi_credentials {}'.format(agent.mac))

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
