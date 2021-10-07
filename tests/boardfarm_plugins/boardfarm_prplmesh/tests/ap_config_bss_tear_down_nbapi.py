# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest
import environment


class ApConfigBSSTeardownNbapi(PrplMeshBaseTest):
    """Check SSID is still available after being torn down

            Devices used in test setup:
            AP1 - Agent1 [DUT]
            GW - Controller

    """

    def check_teardown(self, controller, enabled_aps=[]):
        nbapi_path = 'Device.WiFi.DataElements.Network.AccessPoint'
        existing_aps = controller.nbapi_list(nbapi_path)
        bands = [param for param in existing_aps['parameters'] if "Band" in param]
        for instance in existing_aps['instances']:
            instance_info = controller.nbapi_get(f"{nbapi_path}.{instance['index']}")
            for band in bands:
                if instance_info[band] and band not in enabled_aps:
                    self.fail(f"{band} found enabled ({instance_info['SSID']})")

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        # Same test as the previous one but using CLI instead of dev_send_1905

        ssid = 'Boardfarm-Tests-24G-3-cli'
        self.configure_ssids_clear()
        self.configure_ssid(ssid, "Fronthaul", {'Band2_4G': True})
        controller.nbapi_command("Device.WiFi.DataElements.Network", "AccessPointCommit")

        # Wait until the connection map is updated:
        self.wait_radios_enabled()

        radio_0_vap_0 = agent.radios[0].get_vap(ssid)
        if not radio_0_vap_0:
            self.fail("Radio 0 vap {} not found".format(ssid))

        vap_bss_type = radio_0_vap_0.get_bss_type()

        if vap_bss_type != environment.BssType.Fronthaul:
            self.fail(
                f"Radio 0 vap {ssid} bss type is {vap_bss_type.name} "
                "when it should be Fronthaul")

        self.check_teardown(controller, ['Band2_4G'])

        for vap in agent.radios[0].vaps:
            vap_ssid = vap.get_ssid()
            if vap_ssid not in (ssid, 'N/A'):
                self.fail(f'Wrong SSID: {vap_ssid} instead of {ssid}')

        for vap in agent.radios[1].vaps:
            vap_ssid = vap.get_ssid()
            if vap_ssid != 'N/A':
                self.fail(f'Wrong SSID: {vap_ssid} instead torn down')

        self.checkpoint()

        self.configure_ssids_clear()
        controller.nbapi_command("Device.WiFi.DataElements.Network", "AccessPointCommit")

        # Wait until the connection map is updated:
        self.wait_radios_enabled()

        self.check_teardown(controller)
