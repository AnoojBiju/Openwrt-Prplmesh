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
                   << " FSM: " << fsm_state_to_string(m_state[radio_iface].state) << " --> "       \
                   << fsm_state_to_string(new_state);                                              \
        m_state[radio_iface].state = new_state;                                                    \
    })

const std::string ChannelScanTask::fsm_state_to_string(eState status)
{
    switch (status) {
    case eState::INIT:
        return "INIT";
    case eState::IDLE:
        return "IDLE";
    default:
        LOG(ERROR) << "state argument doesn't have an enum";
        break;
    }
    return std::string();
}

ChannelScanTask::ChannelScanTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SCAN), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ChannelScanTask::work()
{
    for (auto &state_kv : m_state) {
        const auto &radio_iface = state_kv.first;
        auto &state_status      = state_kv.second;
        switch (state_status.state) {
        case eState::UNCONFIGURED: {
            //waiting for START_CHANNEL_SCAN event to initialize m_state with radio list.
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
    case START_CHANNEL_SCAN: {
        auto db = AgentDB::get();
        for (const auto &radio : db->get_radios_list()) {
            if (!radio) {
                continue;
            }

            if (event_obj) {
                auto specific_iface_ptr = reinterpret_cast<const std::string *>(event_obj);
                if (*specific_iface_ptr != radio->front.iface_name) {
                    continue;
                }
            }

            LOG(DEBUG) << "starting scan channel on radio_iface=" << radio->front.iface_name;
            FSM_MOVE_STATE(radio->front.iface_name, eState::INIT);
        }
        // Call work() to not waste time, and start channel scan.
        work();
        break;
    }
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ChannelScanTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                  std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}
