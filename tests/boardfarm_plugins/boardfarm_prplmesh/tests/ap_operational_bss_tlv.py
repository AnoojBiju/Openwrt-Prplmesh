###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug

import time


class ApOperationalBss(PrplMeshBaseTest):
    ''' Check fields in ApOperationalBSS TLV '''

    def runTest(self):
        try:
            controller = self.dev.lan.controller_entity
            agent = self.dev.DUT.agent_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)
        self.checkpoint()
        controller.beerocks_cli_command('bml_clear_wifi_credentials {}'.format(agent.mac))
        controller.beerocks_cli_command('bml_set_wifi_credentials {} {} {} {} {}'
                                        .format(agent.mac,
                                                "Multi-AP-24G-5g-1",
                                                "maprocks1",
                                                "24g-5g",
                                                "fronthaul"))
        controller.beerocks_cli_command('bml_update_wifi_credentials {}'.format(agent.mac))
        time.sleep(3)
        debug("Send 1905 a Topology Query message")
        mid = controller.dev_send_1905(agent.mac, 0x0002)
        time.sleep(1)
        topology_resp = self.check_cmdu_type_single("Topology Response message", 0x0003,
                                                    agent.mac, controller.mac, mid)
        ap_op_bss_tlv = self.check_cmdu_has_tlv_single(topology_resp, 0x83)

        if int(ap_op_bss_tlv.ap_bss_radio_count) != len(agent.radios):
            self.fail("No radios found in AP Operational TLV.")
        if not hasattr(ap_op_bss_tlv, 'ap_operational_bss_radio'):
            self.fail("Missing ap_operational_bss_radio.")

        for radio in ap_op_bss_tlv.ap_operational_bss_radio:
            if not hasattr(radio, 'ap_radio_identifier'):
                self.fail("Missing ap_radio_identifier.")
            radio_id = radio.ap_radio_identifier
            current_radio = next((r for r in agent.radios if r.mac == radio_id), None)
            if current_radio is None:
                self.fail("Reported non-existent radio {}".format(radio_id))
            if int(radio.ap_bss_intf_count) == 0:
                self.fail("No AP BSS interface found. bss_local_interface_list is empty.")
            if hasattr(radio, 'ap_operational_bss_local_interface') == 0:
                self.fail("Missing ap_operational_bss_local_interface.")
            for bss_interface in radio.ap_operational_bss_local_interface:
                self.safe_check_obj_attribute(bss_interface, 'ap_bss_local_intf_addr',
                                              current_radio.vaps[0].bssid,
                                              "Wrong BSSID: {}, expected: {}".format(
                                                  bss_interface.ap_bss_local_intf_addr,
                                                  current_radio.vaps[0].bssid))
                self.safe_check_obj_attribute(bss_interface, 'ap_bss_local_intf_ssid',
                                              "Multi-AP-24G-5g-1",
                                              "Wrong mac SSID: {}, expected: Multi-AP-24G-5g-1"
                                              .format(bss_interface.ap_bss_local_intf_ssid))
        debug("No errors found in the AP Operational TLV.")

    @ classmethod
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
