###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug


class ClientAssociationDummy(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
            sta = self.dev.wifi
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        debug("Connect dummy STA to wlan0")
        sta.wifi_connect_check(agent.radios[0].vaps[0])

        time.sleep(1)

        debug("Send client association control request to the chosen BSSID (UNBLOCK)")
        print('client_allow {} {}'.format(sta.mac, agent.radios[1].mac))
        controller.beerocks_cli_command('client_allow {} {}'.format(sta.mac, agent.radios[1].mac))

        time.sleep(1)

        debug("Confirming Client Association Control Request message was received (UNBLOCK)")
        self.check_log(agent.radios[1],
                       r"Got client allow request for {}".format(sta.mac), timeout=20)

        debug("Send client association control request to all other (BLOCK) ")
        controller.beerocks_cli_command('client_disallow {} {}'.format(sta.mac,
                                                                       agent.radios[0].mac))
        time.sleep(1)

        debug("Confirming Client Association Control Request message was received (BLOCK)")
        self.check_log(agent.radios[0],
                       r"Got client disallow request for {}".format(sta.mac), timeout=20)

        # TODO client blocking not implemented in dummy bwl

        # Check in connection map
        conn_map = controller.get_conn_map()
        map_radio = conn_map[agent.mac].radios[agent.radios[0].mac]
        map_vap = map_radio.vaps[agent.radios[0].vaps[0].bssid]
        if sta.mac not in map_vap.clients:
            self.fail("client {} not in conn_map, clients: {}".format(sta.mac, map_vap.clients))

        # Associate with other radio, check that conn_map is updated
        agent.radios[0].vaps[0].disassociate(sta)
        agent.radios[1].vaps[0].associate(sta)
        time.sleep(1)  # Wait for conn_map to be updated
        conn_map = controller.get_conn_map()
        map_agent = conn_map[agent.mac]
        map_radio1 = map_agent.radios[agent.radios[1].mac]
        map_vap1 = map_radio1.vaps[agent.radios[1].vaps[0].bssid]
        if sta.mac not in map_vap1.clients:
            self.fail("client {} not in conn_map, clients: {}".format(sta.mac, map_vap1.clients))
        map_radio0 = map_agent.radios[agent.radios[0].mac]
        map_vap0 = map_radio0.vaps[agent.radios[0].vaps[0].bssid]
        if sta.mac in map_vap0.clients:
            self.fail("client {} still in conn_map, clients: {}".format(sta.mac, map_vap0.clients))

        # Associate with other radio implies disassociate from first
        agent.radios[0].vaps[0].associate(sta)
        time.sleep(1)  # Wait for conn_map to be updated
        conn_map = controller.get_conn_map()
        map_agent = conn_map[agent.mac]
        map_radio1 = map_agent.radios[agent.radios[1].mac]
        map_vap1 = map_radio1.vaps[agent.radios[1].vaps[0].bssid]
        if sta.mac in map_vap1.clients:
            self.fail("client {} still in conn_map, clients: {}".format(sta.mac, map_vap1.clients))
        map_radio0 = map_agent.radios[agent.radios[0].mac]
        map_vap0 = map_radio0.vaps[agent.radios[0].vaps[0].bssid]
        if sta.mac not in map_vap0.clients:
            self.fail("client {} not in conn_map, clients: {}".format(sta.mac, map_vap0.clients))

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
