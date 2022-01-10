# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

import time

from boardfarm.exceptions import SkipTest
from opts import debug

from .prplmesh_base_test import PrplMeshBaseTest


class TopologyDiscoveryBurst(PrplMeshBaseTest):
    """Send Burst of Topology Discovery messages

    Devices used in test setup:
    AP1 - Agent1 [DUT]
    GW - Controller

    """

    def runTest(self):
        # Locate test participants
        try:
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        controller.cmd_reply(
            "CUSTOM_CMD,cmd,discovery_burst,base_mac,84:d3:2a:04:02:00,repeats,214"
        )

        debug("")
        time.sleep(5)
