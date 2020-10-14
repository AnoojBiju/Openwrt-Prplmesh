/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "dynamic_channel_selection_task.h"
#include "../agent_db.h"
#include <easylogging++.h>

using namespace beerocks;

#define FSM_MOVE_STATE(radio_iface, new_state)                                                     \
    ({                                                                                             \
        LOG(TRACE) << "DYNAMIC_CHANNEL_SELECTION " << radio_iface                                  \
                   << " FSM: " << fsm_state_to_string(m_state[radio_iface].state) << " --> "       \
                   << fsm_state_to_string(new_state);                                              \
        m_state[radio_iface].state = new_state;                                                    \
    })

const std::string ApDynamicChannelSelectionTask::fsm_state_to_string(eState status)
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

ApDynamicChannelSelectionTask::ApDynamicChannelSelectionTask(backhaul_manager &btl_ctx,
                                                             ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::DYNAMIC_CHANNEL_SELECTION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ApDynamicChannelSelectionTask::work()
{
    for (auto &state_kv : m_state) {
        const auto &radio_iface = state_kv.first;
        auto &state_status      = state_kv.second;
        switch (state_status.state) {
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

void ApDynamicChannelSelectionTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ApDynamicChannelSelectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                const sMacAddr &src_mac,
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

