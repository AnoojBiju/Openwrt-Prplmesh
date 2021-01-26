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

        previous_line_nb = 0
        for attempt in range(1, 4):
            print("Resetting agent 1")
            agent.ucc_socket.cmd_reply("dev_reset_default,devrole,agent,program,map,type,DUT")
            print("Checking if it was actually reset (after line {})".format(previous_line_nb + 1))
            (found, matched_line_nb, _) = self.check_log(agent, "FSM: OPERATIONAL --> RESTART",
                                                         previous_line_nb + 1)
            if found:
                print("Matched at line {}".format(matched_line_nb))
            if matched_line_nb <= previous_line_nb:
                self.fail("The agent was not reset on attempt {}".format(attempt))
            previous_line_nb = matched_line_nb

            time.sleep(10)
            agent.ucc_socket.cmd_reply("dev_set_config,backhaul,eth")
            time.sleep(10)
