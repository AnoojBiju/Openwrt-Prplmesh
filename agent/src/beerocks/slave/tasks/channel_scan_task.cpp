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
