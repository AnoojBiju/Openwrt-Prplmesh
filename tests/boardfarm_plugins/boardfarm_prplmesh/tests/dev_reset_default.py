###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest


class DevResetDefault(PrplMeshBaseTest):

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        agent.ucc_socket.cmd_reply("dev_reset_default,devrole,agent,program,map,type,DUT")
        self.checkpoint()
        time.sleep(2)
        self.check_no_cmdu_type("autoconfig search while in reset", 0x0007, agent.mac)
        self.checkpoint()
        agent.ucc_socket.cmd_reply("dev_set_config,backhaul,eth")
        time.sleep(2)
        self.check_cmdu_type("autoconfig search", 0x0007, agent.mac)

        # After dev_reset_default there is a delay between the auto_config message to the moment,
        # that the sockets to the son_slaves are open. Add a delay to make sure that the son_slaves
        # are operational before continuing to the next test.
        time.sleep(3)

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
