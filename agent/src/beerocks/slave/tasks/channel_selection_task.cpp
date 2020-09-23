/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "channel_selection_task.h"
#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

namespace beerocks {

ChannelSelectionTask::ChannelSelectionTask(backhaul_manager &btl_ctx,
                                           ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SELECTION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool ChannelSelectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                       std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_REQUEST_MESSAGE: {
        handle_channel_selection_request(cmdu_rx, src_mac);
        // According to the WFA documentation, each radio should send channel selection
        // response even if that radio was not marked in the request. After filling radio
        // mac vector need to do forwarding for the channel selection request to all slaves.
        // In this scope return false forwards the message to the son_slave.
        return false;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void ChannelSelectionTask::handle_channel_selection_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                            const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    LOG(DEBUG) << "Forwarding CHANNEL_SELECTION_REQUEST to son_slave, mid=" << std::hex << mid;

    // Clear previous request, if any
    m_btl_ctx.m_expected_channel_selection.requests.clear();
    m_btl_ctx.m_expected_channel_selection.responses.clear();

    m_btl_ctx.m_expected_channel_selection.mid = mid;

    auto db = AgentDB::get();

    // Save radio mac for each connected radio
    for (const auto &radio : db->get_radios_list()) {
        m_btl_ctx.m_expected_channel_selection.requests.emplace_back(radio->front.iface_mac);
    }

}

} // namespace beerocks
