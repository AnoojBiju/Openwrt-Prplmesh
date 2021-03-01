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
        auto &agent_mac   = agent.first;
        auto agent_status = agent.second;

        // Triggering a scan request for a busy agent will result in the abort
        // of the running scan on that agent. Therefore, triggering of a new scan
        // will only be performed after the current scan is complete (marked by idle agent).
        if (!is_agent_idle_with_pending_radio_scans(agent_status)) {
            continue;
        }

        auto abort_active_scans_in_current_agent = [&]() {
            LOG(ERROR) << "aborting all scans for agent " << agent.first;

            // remove all radio_scan_request in-progress from agent queue
            auto scan_it = agent.second.radio_scans.begin();
            while (scan_it != agent_status.radio_scans.end()) {
                if (scan_it->second.status != eRadioScanStatus::PENDING) {
                    auto &radio_mac = scan_it->first;
                    LOG(WARNING) << "aborting scan for radio: " << radio_mac;
                    database.set_channel_scan_in_progress(radio_mac, false, is_single_scan);
                    database.set_channel_scan_results_status(
                        radio_mac, beerocks::eChannelScanStatusCode::INTERNAL_FAILURE,
                        is_single_scan);

                    scan_it = agent_status.radio_scans.erase(scan_it);
                } else {
                    ++scan_it;
                }
            }

            agent.second.status = eAgentStatus::IDLE;
        };

        // Helper lambda - Add a new radio to the channel scan request tlv.
        auto add_radio_to_channel_scan_request_tlv =
            [&](std::shared_ptr<wfa_map::tlvProfile2ChannelScanRequest> &channel_scan_request_tlv,
                sMacAddr radio_mac) -> bool {
            // Helper lambda - Add a new operating_class to a radio in channel scan request tlv.
            auto add_operating_classes_to_radio =
                [&](std::shared_ptr<wfa_map::cRadiosToScan> radio_list_entry,
                    sMacAddr radio_mac) -> bool {
                // Get parent agent mac from radio mac
                auto radio_mac_str = tlvf::mac_to_string(radio_mac);
                auto ire           = database.get_node_parent_ire(radio_mac_str);
                if (ire.empty()) {
                    LOG(ERROR) << "Failed to get node_parent_ire!";
                    return false;
                }
                auto ire_mac = tlvf::mac_from_string(ire);

                // Get channel pool for this radio scan request from DB
                auto &current_channel_pool =
                    database.get_channel_scan_pool(radio_mac, is_single_scan);
                if (current_channel_pool.empty()) {
                    LOG(ERROR) << "Empty channel pool is not supported. please set channel pool "
                                  "for radio mac="
                               << radio_mac;
                    return false;
                }

                if (current_channel_pool.size() > beerocks::message::SUPPORTED_CHANNELS_LENGTH) {
                    LOG(ERROR) << "channel_pool is too big [" << int(current_channel_pool.size())
                               << "] on mac=" << radio_mac;
                    return false;
                }

                auto &radio_scans        = m_agents_status_map[ire_mac].radio_scans[radio_mac];
                radio_scans.channel_pool = current_channel_pool;

                // Convert channels list to operating_class: channels list
                std::unordered_map<uint8_t, std::set<uint8_t>> operating_class_to_classes_map;

                for (auto const &ch : current_channel_pool) {
                    beerocks::message::sWifiChannel channel;
                    channel.channel = ch;
                    channel.channel_bandwidth =
                        database.get_node_bw(tlvf::mac_to_string(radio_mac));
                    auto operating_class = wireless_utils::get_operating_class_by_channel(channel);
                    operating_class_to_classes_map[operating_class].insert(ch);
                    LOG(INFO) << "ch:" << channel.channel << ", bw:" << channel.channel_bandwidth
                              << " => op_class:" << operating_class;
                }

                for (auto const &op_class : operating_class_to_classes_map) {

                    // Create radio list (cRadiosToScan) object
                    auto operating_classes_list = radio_list_entry->create_operating_classes_list();
                    if (!operating_classes_list) {
                        LOG(ERROR) << "create_operating_classes_list() failed";
                        return false;
                    }

                    // Fill operating_classes list object
                    // Set operating_classes uid as operating_classes mac address
                    operating_classes_list->operating_class() = op_class.first;

                    // Fill channels list field
                    std::vector<uint8_t> ch_list(op_class.second.begin(), op_class.second.end());
                    if (!operating_classes_list->set_channel_list(ch_list.data(), ch_list.size())) {
                        LOG(ERROR) << "set_channel_list() failed";
                        return false;
                    }

                    // Add operating_classes list object to TLV
                    if (!radio_list_entry->add_operating_classes_list(operating_classes_list)) {
                        LOG(ERROR) << "add_operating_classes_list() failed";
                        return false;
                    }
                }
                return true;
            };

            // Create radio list (cRadiosToScan) object
            auto radio_list = channel_scan_request_tlv->create_radio_list();
            if (!radio_list) {
                LOG(ERROR) << "create_radio_list() failed";
                return false;
            }

            // Fill radio list object
            // Set radio uid as radio mac address
            radio_list->radio_uid() = radio_mac;

            // If the "Perform Fresh Scan" bit is set to 0 (RETURN_STORED_RESULTS_OF_LAST_SUCCESSFUL_SCAN),
            // Number of Operating Classes field shall be set to zero and the following fields shall be omitted:
            // Operating Class, Number of Channels, Channel List.

            // Fill Operating Class, Number of Channels and Channel List only if "Perform Fresh Scan" bit is set to 1.
            if (channel_scan_request_tlv->perform_fresh_scan() ==
                wfa_map::tlvProfile2ChannelScanRequest::ePerformFreshScan::
                    PERFORM_A_FRESH_SCAN_AND_RETURN_RESULTS) {
                // Fill Operating Class and Channel List
                if (!add_operating_classes_to_radio(radio_list, radio_mac)) {
                    return false;
                };
            }

            // Add radio list object to TLV
            if (!channel_scan_request_tlv->add_radio_list(radio_list)) {
                LOG(ERROR) << "add_radio_list() failed";
                return false;
            }
            return true;
        };

        // Agent require triggering - trigger all scans in agent
        uint16_t mid;
        std::shared_ptr<wfa_map::tlvProfile2ChannelScanRequest> channel_scan_request_tlv = nullptr;

        // Create channel scan request message
        if ((!create_channel_scan_request_message(agent_mac, mid, channel_scan_request_tlv)) ||
            (!channel_scan_request_tlv)) {
            LOG(ERROR) << "create_channel_scan_request_message() failed for agent " << agent_mac;
            abort_active_scans_in_current_agent();
            continue; //CMDU creation failed - Trigger the next agent
        }

        // Add all radio scans in current agent to radio_list in channel_scan_request_tlv.
        bool success = true;
        for (auto &radio_scan_request : agent.second.radio_scans) {

            radio_scan_request.second.mid = mid;
            //TODO: Skip ACK until ACK message can be routed back to controller task.
            //      (required knowing the mid of outgoing messages)
            //      assume scan request was received and acknowledged by the agent for now.
            //radio_scan_request.second.status = eRadioScanStatus::TRIGGERED_WAIT_FOR_ACK;
            radio_scan_request.second.status = eRadioScanStatus::SCAN_IN_PROGRESS;
            LOG(DEBUG) << "Triggering a scan for radio " << radio_scan_request.first;

            // TODO:Assuming single scan only for now
            auto &radio_mac = radio_scan_request.first;
            database.set_channel_scan_in_progress(radio_mac, true, is_single_scan);

            // Add the radio scan details to the sent message.
            if (!add_radio_to_channel_scan_request_tlv(channel_scan_request_tlv, radio_mac)) {
                // Failed to add radio to radio_list in channel_scan_request_tlv
                LOG(ERROR) << "add_radio_to_channel_scan_request_tlv() failed for radio "
                           << radio_mac;
                success = false;
                break;
            }
        }
        if (!success) {
            abort_active_scans_in_current_agent();
            continue; //tlv creation failed - Trigger the next agent
        }

        // Create channel scan request extended message (vendor specific tlv)
        if (database.is_prplmesh(agent_mac)) {
            auto channel_scan_request_extension_vs_tlv = beerocks::message_com::add_vs_tlv<
                beerocks_message::tlvVsChannelScanRequestExtension>(cmdu_tx);

            if (!channel_scan_request_extension_vs_tlv) {
                LOG(ERROR) << "Failed building tlvVsChannelScanRequestExtension message!";
                abort_active_scans_in_current_agent();
                continue; //tlv creation failed - Trigger the next agent
            }

            // Add additional parmeters of all radio scans in current agent
            // to scan_requests_list in channel_scan_request_extension_vs_tlv.
            auto num_of_radios = agent.second.radio_scans.size();
            if (!channel_scan_request_extension_vs_tlv->alloc_scan_requests_list(num_of_radios)) {
                LOG(ERROR) << "Failed to alloc_scan_requests_list(" << num_of_radios << ")!";
                abort_active_scans_in_current_agent();
                continue; //tlv creation failed - Trigger the next agent
            }

            auto scan_request_idx = 0;
            for (auto &radio_scan_request : agent.second.radio_scans) {

                // Add the radio scan details to the extended message.
                auto ap_scan_request_tuple =
                    channel_scan_request_extension_vs_tlv->scan_requests_list(scan_request_idx);
                if (!std::get<0>(ap_scan_request_tuple)) {
                    LOG(ERROR) << "Failed to get element " << scan_request_idx;
                    success = false;
                    break;
                }
                auto &scan_request_extension = std::get<1>(ap_scan_request_tuple);

                auto &radio_mac = radio_scan_request.first;

                // Get current scan request dwell time from DB
                int32_t dwell_time_msec =
                    database.get_channel_scan_dwell_time_msec(radio_mac, is_single_scan);
                if (dwell_time_msec <= 0) {
                    LOG(ERROR) << "invalid dwell_time=" << int(dwell_time_msec);
                    success = false;
                    break;
                }

                auto &radio_scans           = m_agents_status_map[agent_mac].radio_scans[radio_mac];
                radio_scans.dwell_time_msec = dwell_time_msec;

                scan_request_extension.radio_mac     = radio_mac;
                scan_request_extension.dwell_time_ms = dwell_time_msec;
                scan_request_idx++;
            }
        } else {
            LOG(INFO) << "non-prplmesh agent " << agent_mac
                      << ", skip tlvVsChannelScanRequestExtension creation";
        }

        if (!success) {
            abort_active_scans_in_current_agent();
            continue; //tlv creation failed - Trigger the next agent
        }

        // Send CHANNEL_SCAN_REQUEST_MESSAGE to the agent
        //auto first_radio_mac = agent.second.radio_scans.begin()->first;
        success = send_scan_request_to_agent(agent_mac);

        if (!success) {
            abort_active_scans_in_current_agent();
            continue; //sending scan request to one of the agents failed - Trigger the next agent
        }

        agent.second.status  = eAgentStatus::BUSY;
        agent.second.timeout = std::chrono::system_clock::now() +
                               std::chrono::seconds(CHANNEL_SCAN_REPORT_WAIT_TIME_SEC);
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
    auto &radio_mac = scan_request_event.radio_mac;

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

    // Remove all active scans from the agent and mark it as idle.

    //TODO: Insert mid_to_agent_map validation here when mid of outgoing request messages is known.
    //      If radio scan in progress, assume the agent is expecting the current scan report for now.

    auto &agent_mac = scan_report_event.agent_mac;

    auto agent_it = m_agents_status_map.find(agent_mac);
    if (agent_it == m_agents_status_map.end()) {
        // Ignore external scan reports - agent_mac not found in status container;
        return false;
    }

    auto &radio_scans = agent_it->second.radio_scans;

    auto scan_it = radio_scans.begin();
    while (scan_it != radio_scans.end()) {
        if (scan_it->second.status == eRadioScanStatus::SCAN_IN_PROGRESS) {
            //TODO: Insert mid validation here when mid of outgoing request messages is known.
            //      If the radio status is SCAN_IN_PROGRESS, it is assumed to expect the scan report of this agent.
            auto &radio_mac = scan_it->first;
            database.set_channel_scan_in_progress(radio_mac, false, is_single_scan);
            database.set_channel_scan_results_status(
                radio_mac, beerocks::eChannelScanStatusCode::SUCCESS, is_single_scan);
            scan_it = radio_scans.erase(scan_it);
        } else {
            ++scan_it;
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

            // remove all radio_scan_request in-progress from agent queue
            auto scan_it = agent_status.radio_scans.begin();
            while (scan_it != agent_status.radio_scans.end()) {
                if (scan_it->second.status != eRadioScanStatus::PENDING) {
                    auto &radio_mac = scan_it->first;
                    LOG(WARNING) << "Scan request timeout for radio: " << radio_mac
                                 << " - aborting scan";
                    database.set_channel_scan_in_progress(radio_mac, false, is_single_scan);
                    database.set_channel_scan_results_status(
                        radio_mac, beerocks::eChannelScanStatusCode::CHANNEL_SCAN_REPORT_TIMEOUT,
                        is_single_scan);

                    scan_it = agent_status.radio_scans.erase(scan_it);
                } else {
                    ++scan_it;
                }
            }

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
