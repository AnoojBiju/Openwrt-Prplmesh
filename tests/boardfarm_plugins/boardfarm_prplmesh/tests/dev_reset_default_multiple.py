###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
import time

from .prplmesh_base_test import PrplMeshBaseTest
from boardfarm.exceptions import SkipTest


class DevResetDefaultMultiple(PrplMeshBaseTest):
    """Test that dev_reset_default still resets the agent when it's called
        multiple times.

    Devices used in test setup:
        - Agent1 [DUT]

    """

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        for attempt in range(1, 4):
            print("Resetting agent 1")
            agent.ucc_socket.cmd_reply("dev_reset_default,devrole,agent,program,map,type,DUT")

            time.sleep(10)
            print("Resetting agent 1 twice")
            agent.ucc_socket.cmd_reply("dev_reset_default,devrole,agent,program,map,type,DUT")

            time.sleep(1)
            print("Configuring agent 1")
            agent.ucc_socket.cmd_reply("dev_set_config,backhaul,eth")
            time.sleep(10)
