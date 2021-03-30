/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "dynamic_channel_selection_r2_task.h"
#include "../son_actions.h"
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <easylogging++.h>

#define CHANNEL_SCAN_REPORT_WAIT_TIME_SEC 300 //5 Min

// TODO:Assuming single scan only for now
constexpr bool is_single_scan = true;

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

        handle_timeout_in_busy_agents();

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
        auto scan_request_event = reinterpret_cast<const sSingleScanRequestEvent *>(event_obj);
        LOG(TRACE) << "Received TRIGGER_SINGLE_SCAN event for mac:"
                   << scan_request_event->radio_mac;

        handle_single_scan_request_event(*scan_request_event);
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
    case CONTINUOUS_STATE_CHANGED_PER_RADIO: {
        auto scan_request_event =
            reinterpret_cast<const sContinuousScanRequestStateChangeEvent *>(event_obj);
        LOG(TRACE) << "Received CONTINUOUS_STATE_CHANGED_PER_RADIO event for mac:"
                   << scan_request_event->radio_mac << " enable: " << scan_request_event->enable;

        handle_continuous_scan_request_event(*scan_request_event);
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
    return true;
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

bool dynamic_channel_selection_r2_task::trigger_pending_scan_requests() { return true; }

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
    return true;
}

bool dynamic_channel_selection_r2_task::handle_single_scan_request_event(
    const sSingleScanRequestEvent &scan_request_event)
{
    // Add pending scan request for radio to the task status container
    const auto &radio_mac = scan_request_event.radio_mac;

    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto ire           = database.get_node_parent_ire(radio_mac_str);
    if (ire.empty()) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    // Add agent to the container if it doesn't exist yet
    auto ire_mac = tlvf::mac_from_string(ire);
    auto agent   = m_agents_status_map.find(ire_mac);
    if (agent == m_agents_status_map.end()) {
        // Add agent to the queue
        m_agents_status_map[ire_mac] = sAgentScanStatus();
    }

    auto agent_it = m_agents_status_map.find(ire_mac);
    if (agent_it != m_agents_status_map.end()) {
        auto agent_mac      = tlvf::mac_from_string(ire);
        const auto &scan_it = m_agents_status_map[agent_mac].single_radio_scans.find(radio_mac);
        if (scan_it != m_agents_status_map[agent_mac].single_radio_scans.cend()) {
            return false;
        }
    }

    const auto &pool = database.get_channel_scan_pool(scan_request_event.radio_mac, true);
    if (pool.empty()) {
        LOG(TRACE) << "continuous_scan cannot proceed without channel_scan list";
        return false;
    }

    int32_t dwell_time_msec = database.get_channel_scan_dwell_time_msec(radio_mac, true);
    if (dwell_time_msec <= 0) {
        LOG(TRACE) << "continuous_scan cannot proceed without dwell_time value";
        return false;
    }

    m_agents_status_map[ire_mac].single_radio_scans[radio_mac] =
        sAgentScanStatus::sRadioScanRequest();
    m_agents_status_map[ire_mac].single_radio_scans[radio_mac].is_single_scan = true;

    return true;
}

bool dynamic_channel_selection_r2_task::handle_continuous_scan_request_event(
    const sContinuousScanRequestStateChangeEvent &scan_request_event)
{
    // Add pending scan request for radio to the task status container
    const auto &radio_mac = scan_request_event.radio_mac;

    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto ire           = database.get_node_parent_ire(radio_mac_str);
    if (ire.empty()) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    auto agent_mac = tlvf::mac_from_string(ire);

    // If received "enable" add the continuous radio request (and the agent that manages it if it doesn't exist yet).
    // If received "disable" and the radio is in the agent's status map and not in progress, remove it. If after
    // the removal the agent has no radio scan requests (is empty) then it will also be removed.
    // If continuous radio scan request is in progress then we will not remove it and it will be removed when the scan
    // is complete. Otherwise, do nothing.
    const auto &agent = m_agents_status_map.find(agent_mac);
    if (agent == m_agents_status_map.cend()) {
        // Add agent to the queue
        m_agents_status_map[agent_mac] = sAgentScanStatus();
    }
    // If the instruction is to disable the request, remove if pending.
    // If not pending then will be removed when current scan is completed/aborted.
    if (!scan_request_event.enable) {
        // If it's not in the container stop.
        const auto &scan_it = m_agents_status_map[agent_mac].continuous_radio_scans.find(
            scan_request_event.radio_mac);
        if (scan_it == m_agents_status_map[agent_mac].continuous_radio_scans.cend()) {
            return false;
        }
        // If it's not pending stop
        if (scan_it->second.status != eRadioScanStatus::PENDING) {
            LOG(WARNING) << "scan is currently pending will be removed at the next response";
            return false;
        }

        // We can remove it now
        m_agents_status_map[agent_mac].continuous_radio_scans.erase(scan_request_event.radio_mac);

        LOG(DEBUG) << "Continuous Radio Scan"
                   << " mac: " << scan_it->first << " was succesfuly deleted from the container";
        return false;
    }

    if (database.get_channel_scan_interval_sec(scan_request_event.radio_mac) <= 0) {
        LOG(ERROR) << "continuous_scan cannot proceed without channel_scan interval";
        return false;
    }

    const auto &pool = database.get_channel_scan_pool(scan_request_event.radio_mac, false);
    if (pool.empty()) {
        LOG(ERROR) << "continuous_scan cannot proceed without channel_scan list";
        return false;
    }

    int32_t dwell_time_msec = database.get_channel_scan_dwell_time_msec(radio_mac, false);
    if (dwell_time_msec <= 0) {
        LOG(ERROR) << "continuous_scan cannot proceed without dwell_time value";
        return false;
    }

    m_agents_status_map[agent_mac].continuous_radio_scans[radio_mac] =
        sAgentScanStatus::sRadioScanRequest();
    m_agents_status_map[agent_mac].continuous_radio_scans[radio_mac].is_single_scan = false;
    m_agents_status_map[agent_mac].continuous_radio_scans[radio_mac].next_time_scan =
        std::chrono::system_clock::now();

    return true;
}

bool dynamic_channel_selection_r2_task::handle_scan_report_event(
    const sScanReportEvent &scan_report_event)
{

    // Remove all active scans from the agent and mark it as idle.

    //TODO: Insert mid_to_agent_map validation here when mid of outgoing request messages is known.
    //      If radio scan in progress, assume the agent is expecting the current scan report for now.

    auto &agent_mac = scan_report_event.agent_mac;

    auto agent_it = m_agents_status_map.find(agent_mac);
    if (agent_it == m_agents_status_map.end()) {
        // Ignore external scan reports - agent_mac not found in status container;
        return false;
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

    //TODO: Assuming perform_fresh_scan=1 for now => include operating_classes_list.
    channel_scan_request_tlv->perform_fresh_scan() = wfa_map::tlvProfile2ChannelScanRequest::
        ePerformFreshScan::PERFORM_A_FRESH_SCAN_AND_RETURN_RESULTS;

    return true;
}

bool dynamic_channel_selection_r2_task::handle_timeout_in_busy_agents()
{
    // Check all busy agents for timeout
    auto timeout_found = false;
    for (auto &agent : m_agents_status_map) {
        auto &agent_mac    = agent.first;
        auto &agent_status = agent.second;

        if (agent_status.status == eAgentStatus::BUSY &&
            agent_status.timeout <= std::chrono::system_clock::now()) {

            timeout_found = true;
            LOG(WARNING) << "Scan request timeout for agent: " << agent_mac
                         << " - aborting in progress scans";

            agent_status.status = eAgentStatus::IDLE;
        }
    }
    return timeout_found;
}

bool dynamic_channel_selection_r2_task::handle_ieee1905_1_msg(const std::string &src_mac,
                                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{
    return false;
}
