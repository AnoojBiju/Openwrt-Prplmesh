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

bool dynamic_channel_selection_r2_task::handle_scan_request_event() { return true; }

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
