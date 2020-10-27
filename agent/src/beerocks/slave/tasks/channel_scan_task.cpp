/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "channel_scan_task.h"
#include "../agent_db.h"
#include <easylogging++.h>

#include "../backhaul_manager/backhaul_manager_thread.h"

using namespace beerocks;

#define FSM_MOVE_STATE(radio_iface, new_state)                                                     \
    ({                                                                                             \
        LOG(TRACE) << "CHANNEL_SCAN " << radio_iface                                               \
                   << " FSM: " << m_states_string.at(m_state[radio_iface]) << " --> "              \
                   << m_states_string.at(new_state);                                               \
        m_state[radio_iface] = new_state;                                                          \
    })

ChannelScanTask::ChannelScanTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SCAN), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ChannelScanTask::work()
{
    for (auto &state_kv : m_state) {
        const auto &radio_iface = state_kv.first;
        auto &state             = state_kv.second;
        switch (state) {
        case eState::UNCONFIGURED: {
            //waiting for start_scan() call to initialize m_state with radio list.
            break;
        }
        case eState::INIT: {
            FSM_MOVE_STATE(radio_iface, eState::IDLE);
            break;
        }
        case eState::IDLE: {
            break;
        }
        default:
            break;
        }
    }
}

void ChannelScanTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ChannelScanTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                  Socket *sd, std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CHANNEL_SCAN_REQUEST_MESSAGE: {
        return handle_channel_scan_request(cmdu_rx, src_mac);
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void ChannelScanTask::start_scan()
{
    auto db = AgentDB::get();
    for (const auto &radio : db->get_radios_list()) {
        if (!radio) {
            continue;
        }

        LOG(DEBUG) << "Start scan channel on radio_iface=" << radio->front.iface_name;
        FSM_MOVE_STATE(radio->front.iface_name, eState::INIT);
    }
    // Call work() to not waste time, and start channel scan.
    work();
}

bool ChannelScanTask::handle_channel_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    auto channel_scan_request_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2ChannelScanRequest>();
    if (!channel_scan_request_tlv) {
        LOG(ERROR) << "getClass wfa_map::tlvProfile2ChannelScanRequest failed";
        return false;
    }

    LOG(INFO) << "Received CHANNEL_SCAN_REQUEST_MESSAGE, src_mac=" << src_mac
              << ", mid=" << std::hex << mid;

    // Print message content to log - placeholder until full implementation
    const auto &perform_fresh_scan = channel_scan_request_tlv->perform_fresh_scan();
    LOG(DEBUG) << "perform_fresh_scan=" << perform_fresh_scan;

    const auto &radio_list_length = channel_scan_request_tlv->radio_list_length();
    for (int radio_i = 0; radio_i < radio_list_length; ++radio_i) {
        const auto &radio_list = channel_scan_request_tlv->radio_list(radio_i);
        const auto radio_uid   = std::get<1>(radio_list).radio_uid();
        LOG(DEBUG) << "radio_list[" << radio_i << "] radio_uid=" << radio_uid;
    }

    // Build and send ACK message CMDU to the originator.
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return false;
    }

    // Zero Error Code TLVs in this ACK message

    LOG(DEBUG) << "Sending ACK message to the originator, mid=" << std::hex << mid;
    auto db = AgentDB::get();
    if (!m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                       tlvf::mac_to_string(db->bridge.mac))) {
        LOG(ERROR) << "Failed to send ACK_MESSAGE back to controller";
        return false;
    }

    // Send channel scan report back - placeholder until full implementation
    if (!send_channel_scan_report(cmdu_rx, src_mac)) {
        LOG(ERROR) << "Failed to send CHANNEL_SCAN_REPORT_MESSAGE back to controller";
    }

    return true;
}

bool ChannelScanTask::send_channel_scan_report(ieee1905_1::CmduMessageRx &cmdu_rx,
                                               const sMacAddr &src_mac)
{
    // build 1905.1 message CMDU
    auto mid = cmdu_rx.getMessageId();
    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SCAN_REPORT_MESSAGE)) {
        LOG(ERROR) << "Create CMDU of type CHANNEL_SCAN_REPORT_MESSAGE failed";
        return false;
    }

    LOG(DEBUG) << "Sending CHANNEL_SCAN_REPORT_MESSAGE to the originator, mid=" << std::hex << mid;
    auto db = AgentDB::get();
    return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                         tlvf::mac_to_string(db->bridge.mac));
}
