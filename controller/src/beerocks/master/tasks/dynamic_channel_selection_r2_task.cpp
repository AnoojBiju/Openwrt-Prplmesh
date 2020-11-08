/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "dynamic_channel_selection_r2_task.h"
#include "../son_actions.h"
#include <easylogging++.h>

#define FSM_MOVE_STATE(new_state)                                                                  \
    ({                                                                                             \
        LOG(TRACE) << "DYNAMIC_CHANNEL_SELECTION_R2 "                                              \
                   << " FSM: " << m_states_string.at(m_state) << " --> "                           \
                   << m_states_string.at(new_state);                                               \
        m_state = new_state;                                                                       \
    })

dynamic_channel_selection_r2_task::dynamic_channel_selection_r2_task(
    db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_)
    : task("DCS R2 task"), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_)
{
    LOG(TRACE) << "Start dynamic_channel_selection_r2_task(id=" << id << ")";
    database.assign_dynamic_channel_selection_r2_task_id(id);
    m_state = eState::IDLE;
}

void dynamic_channel_selection_r2_task::work()
{
    switch (m_state) {
    case eState::IDLE: {
        break;
    }
    case eState::TRIGGER_SCAN: {
        break;
    }

    default:
        break;
    }
}

void dynamic_channel_selection_r2_task::handle_event(int event_enum_value, void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    case TRIGGER_SINGLE_SCAN: {
        auto scan_request_event = reinterpret_cast<const sScanRequestEvent *>(event_obj);
        LOG(TRACE) << "Received TRIGGER_SINGLE_SCAN event for mac:"
                   << scan_request_event->radio_mac;
        handle_scan_request_event(*scan_request_event);
        break;
    }
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool dynamic_channel_selection_r2_task::handle_scan_request_event(
    const sScanRequestEvent &scan_request_event)
{
    // Add pending scan request for radio to the task status container
    auto radio_mac = scan_request_event.radio_mac;

    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto ire           = database.get_node_parent_ire(radio_mac_str);
    if (ire.empty()) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }
    // Is agent exist in pool
    auto ire_mac = tlvf::mac_from_string(ire);
    auto agent   = m_agents_status_map.find(ire_mac);
    if (agent != m_agents_status_map.end()) {
        // Is radio scan exist in agent
        auto radio_request = agent->second.radio_scans.find(radio_mac);
        if (radio_request != agent->second.radio_scans.end()) {
            // Radio scan request exists - check if radio scan in progress
            if (radio_request->second.status != eRadioScanStatus::PENDING) {
                LOG(ERROR) << "Scan for radio " << radio_mac
                           << " already in progress - ignore new scan request";
                return false;
            }
            // Radio scan request exists but not in progress - override scan request with new request.
            // Note: Currently the scan request does not contain specific informaiton (when pending) - but in the future
            // may include other information to override.
            agent->second.radio_scans.erase(radio_mac);
        }
    } else {
        // Add agent to the queue
        m_agents_status_map[ire_mac] = sAgentScanStatus();
    }

    // Create new radio request (with default values) in request pool
    m_agents_status_map[ire_mac].radio_scans[radio_mac] = sAgentScanStatus::sRadioScanRequest();

    return true;
}
