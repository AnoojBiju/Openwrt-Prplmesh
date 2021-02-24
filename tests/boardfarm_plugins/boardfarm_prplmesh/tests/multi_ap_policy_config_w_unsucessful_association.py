# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from boardfarm.exceptions import SkipTest
from common_flow import CommonFlows


class MultiApPolicyConfigWUnsucessfulAssociation(CommonFlows):
    """
        Devices used in test setup:
        STA1 - WIFI repeater
        AP1 - Agent1 [DUT]

        GW - Controller
    """

    def runTest(self):
        # Locate test participants
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
            sta = self.dev.wifi
        except AttributeError as ae:
            raise SkipTest(ae)

        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)

        self.configure_multi_ap_policy_config_with_unsuccessful_association(
            agent, controller, 0x80, 0x01)
        self.mismatch_psk(agent.radios[0], controller, sta)
