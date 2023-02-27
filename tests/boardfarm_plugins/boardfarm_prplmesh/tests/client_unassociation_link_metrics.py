###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import time

from .prplmesh_base_test import PrplMeshBaseTest
from capi import tlv
from opts import debug


class ClientUnAssociationLinkMetrics(PrplMeshBaseTest):
    ''' This test verifies that a MAUT with an unassociated STA responds to
    an UnAssociated STA Link Metrics Query message with an UnAssociated STA Link Metrics
    Response message containing an UnAssociated STA Link Metrics TLV for the unassociated STA.'''

    def runTest(self):
        # Locate test participants
        agent = self.dev.DUT.agent_entity
        controller = self.dev.lan.controller_entity

        # Regression check
        # Don't connect nonexistent Station
        self.dev.DUT.wired_sniffer.start(self.__class__.__name__ + "-" + self.dev.DUT.name)
        debug("Send link metrics query for unconnected STA")
        controller.ucc_socket.dev_send_1905(agent.mac,
                                            self.ieee1905['eMessageType']
                                            ['UNASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE'],
                                            tlv(self.ieee1905['eTlvTypeMap']
                                                ['TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY'],
                                                '0x73 0x01 {0x24 0x01 {0x11 0x22 0x33 0x44 0x55 0x66}}'))
        time.sleep(1)
