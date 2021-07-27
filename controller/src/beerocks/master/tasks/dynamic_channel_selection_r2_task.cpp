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
    if (agent_scan_status.status != eAgentStatus::IDLE) {
        return false;
    }

    if (agent_scan_status.single_radio_scans.empty() &&
        agent_scan_status.continuous_radio_scans.empty()) {
        LOG(WARNING) << "agent is idle without any pending scans";
        return false;
    }

    // If single radio scan requests is not empty and there's a pending single scan
    if (!agent_scan_status.single_radio_scans.empty()) {
        for (const auto &single_scan : agent_scan_status.single_radio_scans) {
            if (single_scan.second.status == eRadioScanStatus::PENDING) {
                return true;
            }
        }
    }

    // If continuous radio scan requests is not empty and there's
    // a continuous scan that its interval between scans passed
    if (!agent_scan_status.continuous_radio_scans.empty()) {
        for (auto continuous_scan : agent_scan_status.continuous_radio_scans) {
            if (continuous_scan.second.status == eRadioScanStatus::PENDING &&
                sAgentScanStatus::is_continuous_scan_interval_passed(continuous_scan.second)) {
                return true;
            }
        }
    }

    return false;
}

bool dynamic_channel_selection_r2_task::is_scan_pending_for_any_idle_agent()
{
    // Scan m_agents_status_map for idle agents
    for (const auto &agent : m_agents_status_map) {

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

        // A temporary container to hold both scan types
        sAgentScanStatus::RadioScanMap radio_scan_requests_to_trigger;

        // If single radio scans is not empty and there's a pending single scan
        if (!agent_status.single_radio_scans.empty()) {
            for (const auto &single_scan : agent_status.single_radio_scans) {
                radio_scan_requests_to_trigger[single_scan.first] = single_scan.second;
            }
        }

        // Merge both scan containers tentatively while it skips any scans that doesn't meet the requirements.
        if (!agent_status.continuous_radio_scans.empty()) {
            for (const auto &continuous_scan : agent_status.continuous_radio_scans) {
                const auto &scan_it = radio_scan_requests_to_trigger.find(continuous_scan.first);
                if (!sAgentScanStatus::is_continuous_scan_interval_passed(continuous_scan.second) ||
                    scan_it != radio_scan_requests_to_trigger.cend()) {
                    continue;
                }

                radio_scan_requests_to_trigger[continuous_scan.first] = continuous_scan.second;
            }
        }

        // No available scans, skip this agent
        if (radio_scan_requests_to_trigger.empty()) {
            continue;
        }

        // Helper lambda - abort all the requests for the current agent, this is used if
        // something went wrong in one of the TLVF creation process.
        auto abort_active_scans_in_current_agent = [&]() {
            LOG(ERROR) << "aborting all scans for agent " << agent.first;

            if (!agent.second.single_radio_scans.empty()) {
                // remove all radio_scan_request in-progress from agent queue
                auto scan_it = agent.second.single_radio_scans.begin();
                while (scan_it != agent.second.single_radio_scans.end()) {
                    if (scan_it->second.status != eRadioScanStatus::PENDING) {
                        auto &radio_mac = scan_it->first;
                        LOG(WARNING) << "aborting scan for radio: " << radio_mac;
                        database.set_channel_scan_in_progress(radio_mac, false,
                                                              scan_it->second.is_single_scan);
                        database.set_channel_scan_results_status(
                            radio_mac, beerocks::eChannelScanStatusCode::INTERNAL_FAILURE,
                            scan_it->second.is_single_scan);

                        // is it enabled?
                        scan_it = agent.second.single_radio_scans.erase(scan_it);
                    } else {
                        ++scan_it;
                    }
                }
            }

            if (!agent.second.continuous_radio_scans.empty()) {
                auto scan_it = agent.second.continuous_radio_scans.begin();
                while (scan_it != agent.second.continuous_radio_scans.end()) {
                    if (scan_it->second.status != eRadioScanStatus::PENDING) {
                        const auto &radio_mac = scan_it->first;

                        database.set_channel_scan_in_progress(radio_mac, false,
                                                              scan_it->second.is_single_scan);
                        database.set_channel_scan_results_status(
                            radio_mac, beerocks::eChannelScanStatusCode::INTERNAL_FAILURE,
                            scan_it->second.is_single_scan);

                        // is it enabled?
                        if (database.get_channel_scan_is_enabled(scan_it->first)) {
                            LOG(WARNING)
                                << "aborting scan for radio: " << radio_mac << " and is delayed by "
                                << INTERVAL_TIME_BETWEEN_RETRIES_ON_FAILURE_SEC / 60 << "minutes";
                            scan_it->second.next_time_scan =
                                std::chrono::system_clock::now() +
                                std::chrono::seconds(INTERVAL_TIME_BETWEEN_RETRIES_ON_FAILURE_SEC);
                            ++scan_it;
                        } else {
                            LOG(WARNING) << "aborting scan for radio: " << radio_mac;
                            scan_it = agent.second.continuous_radio_scans.erase(scan_it);
                        }
                    } else {
                        ++scan_it;
                    }
                }
            }

            agent.second.status = eAgentStatus::IDLE;
        };

        // Helper lambda - Add a new radio to the channel scan request tlv.
        auto add_radio_to_channel_scan_request_tlv =
            [&](std::shared_ptr<wfa_map::tlvProfile2ChannelScanRequest> &channel_scan_request_tlv,
                sMacAddr radio_mac, bool is_single_scan) -> bool {
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

                // Convert channels list to operating_class: channels list
                std::unordered_map<uint8_t, std::set<uint8_t>> operating_class_to_classes_map;

                for (auto const &ch : current_channel_pool) {
                    auto operating_class = wireless_utils::get_operating_class_by_channel(
                        beerocks::message::sWifiChannel(
                            ch, database.get_node_bw(tlvf::mac_to_string(radio_mac))));
                    operating_class_to_classes_map[operating_class].insert(ch);
                    LOG(INFO) << " => op_class:" << operating_class;
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
        for (auto &radio_scan_request : radio_scan_requests_to_trigger) {
            radio_scan_request.second.mid = mid;

            if (radio_scan_request.second.is_single_scan) {
                agent.second.single_radio_scans[radio_scan_request.first].status =
                    eRadioScanStatus::SCAN_IN_PROGRESS;
            } else {
                agent.second.continuous_radio_scans[radio_scan_request.first].status =
                    eRadioScanStatus::SCAN_IN_PROGRESS;
            }

            LOG(DEBUG) << "Triggering a scan for radio " << radio_scan_request.first << " type: "
                       << std::string(radio_scan_request.second.is_single_scan ? "Single Scan"
                                                                               : "Continuous Scan");
            auto &radio_mac = radio_scan_request.first;
            database.set_channel_scan_in_progress(radio_mac, true,
                                                  radio_scan_request.second.is_single_scan);

            // Add the radio scan details to the sent message.
            if (!add_radio_to_channel_scan_request_tlv(channel_scan_request_tlv, radio_mac,
                                                       radio_scan_request.second.is_single_scan)) {
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
            auto num_of_radios = radio_scan_requests_to_trigger.size();
            if (!channel_scan_request_extension_vs_tlv->alloc_scan_requests_list(num_of_radios)) {
                LOG(ERROR) << "Failed to alloc_scan_requests_list(" << num_of_radios << ")!";
                abort_active_scans_in_current_agent();
                continue; //tlv creation failed - Trigger the next agent
            }

            auto scan_request_idx = 0;
            for (const auto &radio_scan_request : radio_scan_requests_to_trigger) {

                // Add the radio scan details to the extended message.
                auto ap_scan_request_tuple =
                    channel_scan_request_extension_vs_tlv->scan_requests_list(scan_request_idx);
                if (!std::get<0>(ap_scan_request_tuple)) {
                    LOG(ERROR) << "Failed to get element " << scan_request_idx;
                    success = false;
                    break;
                }
                auto &scan_request_extension = std::get<1>(ap_scan_request_tuple);

                const auto &radio_mac = radio_scan_request.first;

                // Get current scan request dwell time from DB
                int32_t dwell_time_msec = database.get_channel_scan_dwell_time_msec(
                    radio_mac, radio_scan_request.second.is_single_scan);
                if (dwell_time_msec <= 0) {
                    LOG(ERROR) << "invalid dwell_time=" << int(dwell_time_msec);
                    success = false;
                    break;
                }

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

bool dynamic_channel_selection_r2_task::is_scan_triggered_for_radio(const sMacAddr &radio_mac,
                                                                    bool is_single_scan)
{
    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto ire           = database.get_node_parent_ire(radio_mac_str);
    if (ire.empty()) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    // If agent not exist - return false
    auto ire_mac      = tlvf::mac_from_string(ire);
    const auto &agent = m_agents_status_map.find(ire_mac);
    if (agent == m_agents_status_map.cend()) {
        return false;
    }

    if (is_single_scan) {
        // If a single scan request for this radio exists and not in pending state - return true
        const auto &radio_single_scan_request = agent->second.single_radio_scans.find(radio_mac);
        if (radio_single_scan_request != agent->second.single_radio_scans.cend()) {
            return (radio_single_scan_request->second.status != eRadioScanStatus::PENDING);
        }
    } else {
        // If a continuous scan request for this radio exists and not in pending state - return true
        const auto &radio_continuous_scan_request =
            agent->second.continuous_radio_scans.find(radio_mac);
        if (radio_continuous_scan_request != agent->second.continuous_radio_scans.cend()) {
            return (radio_continuous_scan_request->second.status != eRadioScanStatus::PENDING);
        }
    }

    return false;
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

    auto agent_status = agent_it->second;

    if (!agent_status.single_radio_scans.empty()) {
        // remove all radio_scan_request in-progress from agent queue
        auto scan_it = agent_it->second.single_radio_scans.begin();
        while (scan_it != agent_it->second.single_radio_scans.end()) {
            if (scan_it->second.status == eRadioScanStatus::SCAN_IN_PROGRESS) {
                auto radio_mac = scan_it->first;
                database.set_channel_scan_in_progress(radio_mac, false,
                                                      scan_it->second.is_single_scan);
                database.set_channel_scan_results_status(radio_mac,
                                                         beerocks::eChannelScanStatusCode::SUCCESS,
                                                         scan_it->second.is_single_scan);

                scan_it = m_agents_status_map[agent_mac].single_radio_scans.erase(scan_it);
            } else {
                ++scan_it;
            }
        }
    }

    if (!agent_status.continuous_radio_scans.empty()) {
        auto scan_it = agent_it->second.continuous_radio_scans.begin();
        while (scan_it != agent_it->second.continuous_radio_scans.end()) {
            if (scan_it->second.status == eRadioScanStatus::SCAN_IN_PROGRESS) {
                auto radio_mac = scan_it->first;
                database.set_channel_scan_in_progress(radio_mac, false,
                                                      scan_it->second.is_single_scan);
                database.set_channel_scan_results_status(radio_mac,
                                                         beerocks::eChannelScanStatusCode::SUCCESS,
                                                         scan_it->second.is_single_scan);

                if (database.get_channel_scan_is_enabled(radio_mac)) {
                    // Reschedule continuous scan
                    auto interval =
                        std::chrono::seconds(database.get_channel_scan_interval_sec(radio_mac));
                    m_agents_status_map[agent_mac].continuous_radio_scans[radio_mac].status =
                        eRadioScanStatus::PENDING;

                    m_agents_status_map[agent_mac]
                        .continuous_radio_scans[radio_mac]
                        .next_time_scan = std::chrono::system_clock::now() + interval;
                    ++scan_it;
                } else {
                    scan_it = m_agents_status_map[agent_mac].continuous_radio_scans.erase(scan_it);
                }
            } else {
                ++scan_it;
            }
        }
    }

    agent_it->second.status = eAgentStatus::IDLE;

    // Remove an empty sAgentScanStatus object
    if (agent_it->second.single_radio_scans.empty() &&
        agent_it->second.continuous_radio_scans.empty()) {
        m_agents_status_map.erase(agent_it);
    }

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
            LOG(ERROR) << "Scan request timeout for agent: " << agent_mac
                       << " - aborting in progress scans";

            if (!agent.second.single_radio_scans.empty()) {
                auto scan_it = agent.second.single_radio_scans.begin();
                while (scan_it != agent_status.single_radio_scans.end()) {
                    if (scan_it->second.status != eRadioScanStatus::PENDING) {
                        auto &radio_mac = scan_it->first;
                        LOG(ERROR) << "Scan request timeout for radio: " << radio_mac
                                   << " - aborting scan";
                        database.set_channel_scan_in_progress(radio_mac, false,
                                                              scan_it->second.is_single_scan);
                        database.set_channel_scan_results_status(
                            radio_mac,
                            beerocks::eChannelScanStatusCode::CHANNEL_SCAN_REPORT_TIMEOUT,
                            scan_it->second.is_single_scan);

                        scan_it = agent_status.single_radio_scans.erase(scan_it);
                    } else {
                        ++scan_it;
                    }
                }
            }

            if (!agent.second.continuous_radio_scans.empty()) {
                auto scan_it = agent.second.continuous_radio_scans.begin();
                while (scan_it != agent_status.continuous_radio_scans.end()) {
                    if (scan_it->second.status != eRadioScanStatus::PENDING) {
                        auto &radio_mac = scan_it->first;
                        database.set_channel_scan_in_progress(radio_mac, false,
                                                              scan_it->second.is_single_scan);
                        database.set_channel_scan_results_status(
                            radio_mac,
                            beerocks::eChannelScanStatusCode::CHANNEL_SCAN_REPORT_TIMEOUT,
                            scan_it->second.is_single_scan);

                        if (database.get_channel_scan_is_enabled(scan_it->first)) {
                            LOG(ERROR)
                                << "Scan request timeout for radio: " << radio_mac
                                << " - aborting scan and it is delayed by"
                                << INTERVAL_TIME_BETWEEN_RETRIES_ON_FAILURE_SEC / 60 << "minutes.";

                            scan_it->second.next_time_scan =
                                std::chrono::system_clock::now() +
                                std::chrono::seconds(INTERVAL_TIME_BETWEEN_RETRIES_ON_FAILURE_SEC);
                        } else {
                            LOG(ERROR) << "Scan request timeout for radio: " << radio_mac
                                       << " - aborting scan";
                            scan_it = agent.second.continuous_radio_scans.erase(scan_it);
                        }
                    }
                }

                agent_status.status = eAgentStatus::IDLE;
            }
        }
    }

    return timeout_found;
}

bool dynamic_channel_selection_r2_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{
    return false;
}
