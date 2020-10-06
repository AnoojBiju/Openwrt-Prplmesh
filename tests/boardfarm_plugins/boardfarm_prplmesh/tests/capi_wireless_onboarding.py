###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest


class CapiWirelessOnboarding(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        # Step 1: reset
        agent.ucc_socket.cmd_reply("dev_reset_default,devrole,agent,program,map,type,DUT")
        self.checkpoint()
        time.sleep(2)
        self.check_no_cmdu_type("autoconfig search while in reset", 0x0007, agent.mac)

        # Step 2: config
        self.checkpoint()
        agent.ucc_socket.cmd_reply("dev_set_config,backhaul,0x{}".format(
            agent.radios[0].mac.replace(':', '')))

        # At this point, the wired backhaul should be removed from the bridge so autoconfig search
        # should still not come through.
        time.sleep(2)
        self.check_no_cmdu_type(
            "autoconfig search while awaiting onboarding", 0x0007, agent.mac)

        # Step 3: start WPS
        agent.ucc_socket.cmd_reply("start_wps_registration,band,24G,WpsConfigMethod,PBC")

        # TODO start WPS on CTT agent as well to complete onboarding
        # On dummy, it does nothing anyway
        time.sleep(2)

        backhaul_mac = agent.ucc_socket.cmd_reply(
            "dev_get_parameter,program,map,ruid,0x{},parameter,macaddr".format(
                agent.radios[0].mac.replace(':', ''))).get('macaddr')

        # prplMesh uses the radio MAC as the backhaul MAC
        assert backhaul_mac == agent.radios[0].mac

    @classmethod
    def teardown_class(cls):
        """Teardown method, optional for boardfarm tests."""
        test = cls.test_obj

        try:
            agent = test.dev.DUT.agent_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        try:
            test.dev.DUT.wired_sniffer.start(test.__class__.__name__ + "-" + test.dev.DUT.name)

            agent.ucc_socket.cmd_reply("dev_reset_default,devrole,agent,program,map,type,DUT")
            test.checkpoint()
            time.sleep(2)
            test.check_no_cmdu_type("autoconfig search while in reset", 0x0007, agent.mac)
            test.checkpoint()
            agent.ucc_socket.cmd_reply("dev_set_config,backhaul,eth")
            time.sleep(2)
            test.check_cmdu_type("autoconfig search", 0x0007, agent.mac)

            # After dev_reset_default there is a delay between the auto_config message to the
            # moment, that the sockets to the son_slaves are open. Add a delay to make sure
            # that the son_slaves are operational before continuing to the next test.
            time.sleep(3)
        finally:
            test.dev.DUT.wired_sniffer.stop()

        try:
            test.dev.DUT.agent_entity.device.send('\003')
        except AttributeError:
            # If AttributeError was raised - we are dealing with dummy devices.
            # We don't have to additionaly send Ctrl+C for dummy devices.
            pass
        # Clean up: reset to ethernet backhaul
