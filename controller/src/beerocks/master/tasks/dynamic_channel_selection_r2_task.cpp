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
        if (is_scan_pending_for_any_idle_agent()) {
            FSM_MOVE_STATE(eState::TRIGGER_SCAN);
        }
        break;
    }
    case eState::TRIGGER_SCAN: {

        if (!trigger_pending_scan_requests()) {
            LOG(ERROR) << "failed to trigger pending scans";
        }

        FSM_MOVE_STATE(eState::IDLE);
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
    case RECEIVED_CHANNEL_SCAN_REPORT: {
        auto scan_report_event = reinterpret_cast<const sScanReportEvent *>(event_obj);
        LOG(TRACE) << "Received RECEIVED_SCAN_RESULTS event from agent mac:"
                   << scan_report_event->agent_mac << ", mid: " << std::hex
                   << scan_report_event->mid;

        handle_scan_report_event(*scan_report_event);
        break;
    }
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool dynamic_channel_selection_r2_task::is_agent_idle_with_pending_radio_scans(
    const sAgentScanStatus &agent_scan_status)
{
    return ((agent_scan_status.status == eAgentStatus::IDLE) &&
            (!agent_scan_status.radio_scans.empty()));
}

bool dynamic_channel_selection_r2_task::is_scan_pending_for_any_idle_agent()
{
    // Scan m_agents_status_map for idle agents
    for (auto &agent : m_agents_status_map) {

        // Triggering a scan request for a busy agent will result in the abort
        // of the running scan on that agent. Therefore, triggering of a new scan
        // will only be performed after the current scan is complete (marked by idle agent).
        // Trigger a scan for idle agents with pending scans:
        if (is_agent_idle_with_pending_radio_scans(agent.second)) {
            return true;
        }
    }
    return false;
}

bool dynamic_channel_selection_r2_task::trigger_pending_scan_requests()
{
    for (auto &agent : m_agents_status_map) {
        auto agent_mac    = agent.first;
        auto agent_status = agent.second;

        // Triggering a scan request for a busy agent will result in the abort
        // of the running scan on that agent. Therefore, triggering of a new scan
        // will only be performed after the current scan is complete (marked by idle agent).
        if (!is_agent_idle_with_pending_radio_scans(agent_status)) {
            continue;
        }

        // Agent require triggering - trigger all scans in agent
        uint16_t mid;
        std::shared_ptr<wfa_map::tlvProfile2ChannelScanRequest> channel_scan_request_tlv = nullptr;

        // Create channel scan request message
        if ((!create_channel_scan_request_message(agent_mac, mid, channel_scan_request_tlv)) ||
            (!channel_scan_request_tlv)) {
            LOG(ERROR) << "create_channel_scan_request_message() failed for agent " << agent_mac;
            return false;
        }

        // Add all radio scans in current agent to radio_list in channel_scan_request_tlv.
        bool succsess = true;
        for (auto &radio_scan_request : agent.second.radio_scans) {

            radio_scan_request.second.mid    = mid;
            radio_scan_request.second.status = eRadioScanStatus::TRIGGERED_WAIT_FOR_ACK;
            LOG(DEBUG) << "Triggering a scan for radio " << radio_scan_request.first;

            // Add the radio scan details to the sent message.
            auto radio_mac = radio_scan_request.first;
            if (!add_radio_to_channel_scan_request_tlv(channel_scan_request_tlv, radio_mac)) {
                // Failed to add radio to radio_list in channel_scan_request_tlv
                LOG(ERROR) << "add_radio_to_channel_scan_request_tlv() failed for radio "
                           << radio_mac;
                succsess = false;
                break;
            }
        }

        if (!succsess) {
            for (auto &radio_scan_request : agent.second.radio_scans) {
                radio_scan_request.second.mid    = INVALID_MID_ID;
                radio_scan_request.second.status = eRadioScanStatus::PENDING;
                LOG(DEBUG) << "Triggering a scan for radio " << radio_scan_request.first
                           << " failed";
            }
            return false;
        }

        // Send CHANNEL_SCAN_REQUEST_MESSAGE to the agent
        //auto first_radio_mac = agent.second.radio_scans.begin()->first;
        succsess = send_scan_request_to_agent(agent_mac);

        if (!succsess) {
            for (auto &radio_scan_request : agent.second.radio_scans) {
                radio_scan_request.second.mid    = INVALID_MID_ID;
                radio_scan_request.second.status = eRadioScanStatus::PENDING;
                LOG(DEBUG) << "Triggering a scan for radio " << radio_scan_request.first
                           << " failed";
            }
            return false;
        }

        agent.second.status   = eAgentStatus::BUSY;
        mid_to_agent_map[mid] = agent_mac;
        LOG(DEBUG) << "Triggered a scan for agent " << agent_mac;
    }
    return true;
}

bool dynamic_channel_selection_r2_task::is_scan_triggered_for_radio(const sMacAddr &radio_mac)
{
    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto ire           = database.get_node_parent_ire(radio_mac_str);
    if (ire.empty()) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    // If agent not exist - return false
    auto ire_mac = tlvf::mac_from_string(ire);
    auto agent   = m_agents_status_map.find(ire_mac);
    if (agent == m_agents_status_map.end()) {
        return false;
    }

    // If scan request for this radio not exist - return false
    auto radio_scan_request = agent->second.radio_scans.find(radio_mac);
    if (radio_scan_request == agent->second.radio_scans.end()) {
        return false;
    }

    return (radio_scan_request->second.status != eRadioScanStatus::PENDING);
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

bool dynamic_channel_selection_r2_task::handle_scan_report_event(
    const sScanReportEvent &scan_report_event)
{
    // Remove all active scans (with the same mid as scan report) from the agent
    // and mark agent as idle
    auto mid = scan_report_event.mid;

    // check if there is an agent waiting for the response
    auto mid_map_it = mid_to_agent_map.find(mid);
    if (mid_map_it == mid_to_agent_map.end()) {
        LOG(ERROR) << "unexpected mid " << std::hex << mid << " in scan report";
        return false;
    }

    auto agent_mac = mid_map_it->second;
    mid_to_agent_map.erase(mid);

    auto agent_it = m_agents_status_map.find(agent_mac);
    if (agent_it == m_agents_status_map.end()) {
        LOG(ERROR) << "Wrong mid_to_agent_map, agent " << agent_mac
                   << " not found in status container";
        return false;
    }

    auto &radio_scans = agent_it->second.radio_scans;

    for (auto scan_it = radio_scans.begin(); scan_it != radio_scans.end(); ++scan_it) {
        if (scan_it->second.status == eRadioScanStatus::SCAN_IN_PROGRESS &&
            scan_it->second.mid == mid) {
            scan_it = radio_scans.erase(scan_it);
        }
    }

    agent_it->second.status = eAgentStatus::IDLE;

    return true;
}

bool dynamic_channel_selection_r2_task::send_scan_request_to_agent(const sMacAddr &agent_mac)
{
    auto agent_mac_str = tlvf::mac_to_string(agent_mac);

    // Send CMDU to agent
    LOG(INFO) << "Send CHANNEL_SCAN_REQUEST_MESSAGE to agent: " << agent_mac_str;
    if (!son_actions::send_cmdu_to_agent(agent_mac_str, cmdu_tx, database)) {
        LOG(ERROR) << "Failed sending message!";
        return false;
    }

    return true;
}

bool son::dynamic_channel_selection_r2_task::create_channel_scan_request_message(
    sMacAddr agent_mac, uint16_t &mid,
    std::shared_ptr<wfa_map::tlvProfile2ChannelScanRequest> &channel_scan_request_tlv)
{
    LOG(TRACE) << "Creating CHANNEL_SCAN_REQUEST CMDU for agent: " << agent_mac;

    // Build 1905.1 message CMDU to send to the controller
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CHANNEL_SCAN_REQUEST_MESSAGE)) {
        LOG(ERROR) << "CMDU creation of type CHANNEL_SCAN_REQUEST_MESSAGE, has failed";
        return false;
    }

    // Add ChannelScanRequest TLV (non vendor specific)
    channel_scan_request_tlv = cmdu_tx.addClass<wfa_map::tlvProfile2ChannelScanRequest>();
    if (!channel_scan_request_tlv) {
        LOG(ERROR) << "addClass tlvProfile2ChannelScanRequest failed";
        return false;
    }

    // Save the mid of the new CMDU message
    // TODO: Currently getMessageId() return 0, Should be replace by the outgoing message id
    //       once MID will be globally assigned and available to the controller.
    mid = cmdu_tx.getMessageId();

    channel_scan_request_tlv->perform_fresh_scan() = wfa_map::tlvProfile2ChannelScanRequest::
        ePerformFreshScan::RETURN_STORED_RESULTS_OF_LAST_SUCCESSFUL_SCAN;

    return true;
}

bool son::dynamic_channel_selection_r2_task::add_radio_to_channel_scan_request_tlv(
    std::shared_ptr<wfa_map::tlvProfile2ChannelScanRequest> &channel_scan_request_tlv,
    sMacAddr radio_mac)
{
    // Create radio list (cRadiosToScan) object
    auto radio_list = channel_scan_request_tlv->create_radio_list();
    if (!radio_list) {
        LOG(ERROR) << "create_radio_list() failed";
        return false;
    }

    // Add radio list object to TLV
    if (!channel_scan_request_tlv->add_radio_list(radio_list)) {
        LOG(ERROR) << "add_radio_list() failed";
        return false;
    }

    // Fill radio list object
    auto radio_i                = channel_scan_request_tlv->radio_list_length() - 1;
    auto radio_list_entry_tuple = channel_scan_request_tlv->radio_list(radio_i);
    if (!std::get<0>(radio_list_entry_tuple)) {
        LOG(ERROR) << "failed to get radio_list entry for radio-index=" << radio_i;
        return false;
    }

    auto &radio_list_entry = std::get<1>(radio_list_entry_tuple);

    // Set radio uid as radio mac address
    radio_list_entry.radio_uid() = radio_mac;

    // If the "Perform Fresh Scan" bit is set to 0 (RETURN_STORED_RESULTS_OF_LAST_SUCCESSFUL_SCAN),
    // Number of Operating Classes field shall be set to zero and the following fields shall be omitted:
    // Operating Class, Number of Channels, Channel List
    // TODO: add a real operating class list from channel_pool in DB
    radio_list_entry.operating_classes_list_length() = 0;

    return true;
}
