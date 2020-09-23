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
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE: {
        (void)handle_slave_channel_selection_response(cmdu_rx, src_mac);
        break;
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

    // Save radio mac for each connected radio
    for (auto &socket : m_btl_ctx.slaves_sockets) {
        m_btl_ctx.m_expected_channel_selection.requests.emplace_back(socket->radio_mac);
    }
}

bool ChannelSelectionTask::handle_slave_channel_selection_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                                   const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received CHANNEL_SELECTION_RESPONSE message, mid=" << std::hex << mid;

    if (mid != m_btl_ctx.m_expected_channel_selection.mid) {
        return false;
    }

    auto channel_selection_response = cmdu_rx.getClass<wfa_map::tlvChannelSelectionResponse>();
    if (!channel_selection_response) {
        LOG(ERROR) << "Failed cmdu_rx.getClass<wfa_map::tlvChannelSelectionResponse>(), mid="
                   << std::hex << mid;
        return false;
    }

    auto db = AgentDB::get();

    m_btl_ctx.m_expected_channel_selection.responses.push_back(
        {channel_selection_response->radio_uid(), channel_selection_response->response_code()});

    // Remove an entry from the processed query
    m_btl_ctx.m_expected_channel_selection.requests.erase(
        std::remove_if(m_btl_ctx.m_expected_channel_selection.requests.begin(),
                       m_btl_ctx.m_expected_channel_selection.requests.end(),
                       [&](sMacAddr const &query) {
                           return channel_selection_response->radio_uid() == query;
                       }),
        m_btl_ctx.m_expected_channel_selection.requests.end());

    if (!m_btl_ctx.m_expected_channel_selection.requests.empty()) {
        return true;
    }

    // We received all responses - prepare and send response message to the controller
    auto cmdu_header =
        m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE);

    if (!cmdu_header) {
        LOG(ERROR) << "Failed building IEEE1905 CHANNEL_SELECTION_RESPONSE_MESSAGE";
        return false;
    }

    for (const auto &response : m_btl_ctx.m_expected_channel_selection.responses) {
        auto channel_selection_response_tlv =
            m_cmdu_tx.addClass<wfa_map::tlvChannelSelectionResponse>();

        if (!channel_selection_response_tlv) {
            LOG(ERROR) << "Failed addClass<wfa_map::tlvChannelSelectionResponse>";
            continue;
        }

        channel_selection_response_tlv->radio_uid()     = response.radio_mac;
        channel_selection_response_tlv->response_code() = response.response_code;
    }

    // Clear the m_expected_channel_selection.responses vector after preparing response to the controller
    m_btl_ctx.m_expected_channel_selection.responses.clear();

    LOG(DEBUG) << "Sending CHANNEL_SELECTION_RESPONSE_MESSAGE, mid=" << std::hex << mid;
    return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(db->controller_info.bridge_mac),
                                         tlvf::mac_to_string(db->bridge.mac));
}

} // namespace beerocks
