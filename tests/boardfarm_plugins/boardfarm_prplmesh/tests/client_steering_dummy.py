# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug
import environment as env
import time


class ClientSteeringDummy(PrplMeshBaseTest):
    """
        Devices used in test setup:
        STA1 - WIFI repeater
        AP1 - Agent1 [DUT]
        AP2 - Agent2 [LAN2]

        GW - Controller

        Dummy STA is connected to AP1 wlan0
        A steer request is sent to AP1 radio 1
        Dummy STA is disconnected from wlan0
        Dummy STA is connected to AP1 wlan2
        All APs radios should get a disallow request, except for AP1 radio 1
        Client Steering Request message is checked of AP1 radio 0
        BTM Report message is checked on GW controller
        ACK message is checked on AP1 radio 0
        GW controller should have a steering a disconnected message refering to STA1
        After 25 seconds all disallowed APs radios should have an allow message
    """

    def runTest(self):
        # Locate test participants
        try:
            sta = self.dev.wifi
            agent1 = self.dev.DUT.agent_entity
            agent2 = self.dev.lan2.agent_entity

            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        sniffer = self.dev.DUT.wired_sniffer
        sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        self.checkpoint()

        debug("Connect dummy STA to wlan0")
        agent1.radios[0].vaps[0].associate(sta)
        time.sleep(1)

        debug("Check dummy STA connected to repeater1 radio")
        self.check_topology_notification(agent1.mac,
                                         [controller.mac, agent2.mac],
                                         sta, env.StationEvent.CONNECT,
                                         agent1.radios[0].vaps[0].bssid)

        self.checkpoint()

        debug("Send steer request ")
        controller.beerocks_cli_command("steer_client {} {}".format(sta.mac,
                                                                    agent1.radios[1].mac))
        time.sleep(1)
        debug("Disconnect dummy STA from wlan0")
        agent1.radios[0].vaps[0].disassociate(sta)
        time.sleep(1)
        self.check_topology_notification(agent1.mac,
                                         [controller.mac, agent2.mac],
                                         sta, env.StationEvent.DISCONNECT,
                                         agent1.radios[0].vaps[0].bssid)

        self.checkpoint()

        debug("Connect dummy STA to wlan2")
        agent1.radios[1].vaps[0].associate(sta)
        time.sleep(1)
        self.check_topology_notification(agent1.mac,
                                         [controller.mac, agent2.mac],
                                         sta, env.StationEvent.CONNECT,
                                         agent1.radios[1].vaps[0].bssid)

        debug("Confirming Client Association Control Request message was received (UNBLOCK)")
        self.check_log(agent1.radios[1], r"Got client allow request")

        debug("Confirming Client Association Control Request message was received (BLOCK)")
        self.check_log(agent1.radios[0], r"Got client disallow request")

        debug("Confirming Client Association Control Request message was received (BLOCK)")
        self.check_log(agent2.radios[0], r"Got client disallow request")

        debug("Confirming Client Association Control Request message was received (BLOCK)")
        self.check_log(agent2.radios[1], r"Got client disallow request")

        debug("Confirming Client Steering Request message was received - mandate")
        self.check_log(agent1.radios[0], r"Got steer request")

        debug("Confirming BTM Report message was received")
        self.check_log(controller, r"CLIENT_STEERING_BTM_REPORT_MESSAGE")

        debug("Confirming ACK message was received")
        self.check_log(agent1.radios[0], r"ACK_MESSAGE")

        debug("Confirm steering success by client connected")
        self.check_log(controller, r"steering successful for sta {}".format(sta.mac))
        self.check_log(controller,
                       r"sta {} disconnected due to steering request".format(sta.mac))

        # Make sure that all blocked agents send UNBLOCK messages at the end of
        # disallow period (default 25 sec)
        time.sleep(25)

        debug("Confirming Client Association Control Request message was received (UNBLOCK)")
        self.check_log(agent1.radios[0], r"Got client allow request")

        debug("Confirming Client Association Control Request message was received (UNBLOCK)")
        self.check_log(agent2.radios[0], r"Got client allow request")

        debug("Confirming Client Association Control Request message was received (UNBLOCK)")
        self.check_log(agent2.radios[1], r"Got client allow request")

        agent1.radios[1].vaps[0].disassociate(sta)

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
