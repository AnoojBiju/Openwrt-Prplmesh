###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
from opts import debug


class ClientCapabilityQueryFailsWithNoSta(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            sta = self.dev.wifi
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        report = self.base_test_client_capability_query(sta)

        debug("Send client capability query for unconnected STA")

        cap_report_tlv = self.check_cmdu_has_tlv_single(report, 0x91)
        self.safe_check_obj_attribute(cap_report_tlv, 'client_capability_result', '0x00000001',
                                      "Capability query was successful for disconnected STA")

        error_tlv = self.check_cmdu_has_tlv_single(report, 0xa3)
        self.safe_check_obj_attribute(error_tlv, 'error_code_reason', '0x00000002',
                                      "Wrong error reason code")
        self.safe_check_obj_attribute(error_tlv, 'error_code_mac_addr', sta.mac,
                                      "Wrong mac address in error code")

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
