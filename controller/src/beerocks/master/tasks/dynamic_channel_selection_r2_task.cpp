/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "dynamic_channel_selection_r2_task.h"
#include "../son_actions.h"
#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <easylogging++.h>
#include <memory>

constexpr std::chrono::seconds CHANNEL_SCAN_REPORT_WAIT_TIME(300);

#define FSM_MOVE_SCAN_STATE(new_state)                                                             \
    ({                                                                                             \
        LOG(TRACE) << "DYNAMIC_CHANNEL_SELECTION_R2 "                                              \
                   << "Scan FSM: " << m_scan_states_string.at(m_scan_state) << " --> "             \
                   << m_scan_states_string.at(new_state);                                          \
        m_scan_state = new_state;                                                                  \
    })
#define FSM_MOVE_SELECTION_STATE(new_state)                                                        \
    ({                                                                                             \
        LOG(TRACE) << "DYNAMIC_CHANNEL_SELECTION_R2 "                                              \
                   << "Selection FSM: " << m_selection_states_string.at(m_selection_state)         \
                   << " --> " << m_selection_states_string.at(new_state);                          \
        m_selection_state = new_state;                                                             \
    })

dynamic_channel_selection_r2_task::dynamic_channel_selection_r2_task(
    db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_)
    : task("DCS R2 task"), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_)
{
    LOG(TRACE) << "Start dynamic_channel_selection_r2_task(id=" << id << ")";
    database.assign_dynamic_channel_selection_r2_task_id(id);
    m_scan_state      = eScanState::IDLE;
    m_selection_state = eSelectionState::IDLE;
}

void dynamic_channel_selection_r2_task::work()
{
    switch (m_scan_state) {
    case eScanState::IDLE: {

        handle_timeout_in_busy_agents();

        if (is_scan_pending_for_any_idle_agent()) {
            FSM_MOVE_SCAN_STATE(eScanState::TRIGGER_SCAN);
        }
        break;
    }
    case eScanState::TRIGGER_SCAN: {

        if (!trigger_pending_scan_requests()) {
            LOG(ERROR) << "failed to trigger pending scans";
        }

        FSM_MOVE_SCAN_STATE(eScanState::IDLE);
        break;
    }

    default:
        break;
    }

    switch (m_selection_state) {
    case eSelectionState::IDLE: {
        if (!m_pending_selection_requests.empty()) {
            if (!remove_invalid_channel_selection_requests()) {
                LOG(ERROR) << "Failed to remove invalid pending scans";
                break;
            }
            if (m_pending_selection_requests.empty()) {
                LOG(INFO)
                    << "All pending selection requests where removed because there were invalid.";
            }
        }
        if (!m_pending_selection_requests.empty()) {
            if (!send_selection_requests()) {
                LOG(ERROR) << "failed to trigger pending scans";
                break;
            }
            m_selection_timeout = std::chrono::steady_clock::now() + CHANNEL_SELECTION_TIMEOUT;
            FSM_MOVE_SELECTION_STATE(eSelectionState::WAIT_FOR_SELECTION_RESPONSE);
        }
    } break;
    case eSelectionState::WAIT_FOR_SCAN: {
        if (m_selection_timeout < std::chrono::steady_clock::now()) {
            LOG(ERROR) << "Timed out while waiting for the Channel Scan to complete!";
            handle_timeout_in_selection_flow();
            FSM_MOVE_SELECTION_STATE(eSelectionState::IDLE);
        }
    } break;
    case eSelectionState::WAIT_FOR_PREFERENCE: {
        if (m_selection_timeout < std::chrono::steady_clock::now()) {
            LOG(ERROR) << "Timed out while waiting for Channel Preference Report!";
            handle_timeout_in_selection_flow();
            // Without a newer preference, the controller will use the agent's latest received preference
            FSM_MOVE_SELECTION_STATE(eSelectionState::IDLE);
        }
    } break;
    case eSelectionState::WAIT_FOR_SELECTION_RESPONSE: {
        if (m_selection_timeout < std::chrono::steady_clock::now()) {
            LOG(ERROR) << "Timed out while waiting for Channel Selection Response!";
            handle_timeout_in_selection_flow();
            FSM_MOVE_SELECTION_STATE(eSelectionState::IDLE);
        }
    } break;
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
                   << scan_report_event->agent_mac
                   << ", timestamp: " << scan_report_event->ISO_8601_timestamp;

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
    case TRIGGER_ON_DEMAND_CHANNEL_SELECTION: {
        auto on_demand_request_event =
            reinterpret_cast<const sOnDemandChannelSelectionEvent *>(event_obj);
        LOG(TRACE) << "Received TRIGGER_ON_DEMAND_CHANNEL_SELECTION event";
        handle_on_demand_channel_selection_request_event(*on_demand_request_event);
        break;
    }
    case REQUEST_NEW_PREFERENCE: {
        auto new_preference_request_event =
            reinterpret_cast<const sPreferenceRequestEvent *>(event_obj);
        LOG(TRACE) << "Received REQUEST_NEW_PREFERENCE event";
        handle_preference_request_event(*new_preference_request_event);
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
    // Scan m_agents_scan_status_map for idle agents
    for (const auto &agent : m_agents_scan_status_map) {

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
    for (auto &agent : m_agents_scan_status_map) {
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

        std::set<node::radio::channel_scan_report::channel_scan_report_key> scan_report_index;

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
                if (ire == beerocks::net::network_utils::ZERO_MAC) {
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

                auto print_pool =
                    [](const std::unordered_set<uint8_t> &channel_pool) -> std::string {
                    std::ostringstream oss;
                    oss << "[ ";
                    for (const auto &elem : channel_pool) {
                        oss << int(elem) << " ";
                    }
                    oss << "]";
                    return oss.str();
                };
                LOG(ERROR) << "Found channel pool: " << print_pool(current_channel_pool);

                // Convert channels list to operating_class: channels list
                std::unordered_map<uint8_t, std::set<uint8_t>> operating_class_to_classes_map;

                for (auto const &ch : current_channel_pool) {
                    auto operating_class = wireless_utils::get_operating_class_by_channel(
                        beerocks::message::sWifiChannel(ch,
                                                        beerocks::eWiFiBandwidth::BANDWIDTH_20));
                    // Check if channel has a valid operating class in a 20MHz band
                    if (operating_class == 0) {
                        // Skip unsupported channel
                        continue;
                    }
                    operating_class_to_classes_map[operating_class].insert(ch);
                    // Add Operating-Class & Channel-Number pair to the scan report index.
                    // This will be used later when handling the report back.
                    scan_report_index.insert(std::make_pair(operating_class, ch));
                    LOG(INFO) << "Setting channel: " << ch << " => op_class:" << operating_class;
                }

                if (operating_class_to_classes_map.empty()) {
                    LOG(ERROR) << "Unable to send request with no Operating Classes";
                    return false;
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

            // Add the report index to the radio scan element.
            // The index contains a set of [Operating-Class,Channel-Number] pairs.
            // Later we will use the index to match an incoming report to its matching request.
            if (radio_scan_request.second.is_single_scan) {
                agent.second.single_radio_scans[radio_mac].scan_report_index = scan_report_index;
            } else {
                agent.second.continuous_radio_scans[radio_mac].scan_report_index =
                    scan_report_index;
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
                if (dwell_time_msec < 0) {
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
        agent.second.timeout = std::chrono::system_clock::now() + CHANNEL_SCAN_REPORT_WAIT_TIME;
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
    if (ire == beerocks::net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    // If agent not exist - return false
    const auto &agent = m_agents_scan_status_map.find(ire);
    if (agent == m_agents_scan_status_map.cend()) {
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
    auto ire_mac       = database.get_node_parent_ire(radio_mac_str);
    if (ire_mac == beerocks::net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    // Assume we already have an agent handler
    bool create_new_agent = false;

    if (m_agents_scan_status_map.find(ire_mac) != m_agents_scan_status_map.end()) {
        // If agent already exists, make sure there aren't any pending scans.
        const auto &scan_it = m_agents_scan_status_map[ire_mac].single_radio_scans.find(radio_mac);
        if (scan_it != m_agents_scan_status_map[ire_mac].single_radio_scans.end()) {
            LOG(DEBUG) << "A single scan on agent: " << ire_mac << " radio: " << radio_mac
                       << " already exists.";
            // If the scan is pending to be triggered, return True.
            // Otherwise the scan is in progress or pending ACK, return False.
            return (scan_it->second.status == eRadioScanStatus::PENDING);
        }
    } else {
        // We need to create a new agent handler
        create_new_agent = true;
    }

    const auto &pool = database.get_channel_scan_pool(scan_request_event.radio_mac, true);
    if (pool.empty()) {
        LOG(TRACE) << "single scan cannot proceed without channel_scan list";
        return false;
    }

    int32_t dwell_time_msec = database.get_channel_scan_dwell_time_msec(radio_mac, true);
    if (dwell_time_msec < 0) {
        LOG(TRACE) << "single scan cannot proceed without dwell_time value";
        return false;
    }

    // Check if we need to create a new agent handler
    if (create_new_agent) {
        // Add agent to the queue
        m_agents_scan_status_map.insert({ire_mac, {}});
    }

    m_agents_scan_status_map[ire_mac].single_radio_scans[radio_mac] =
        sAgentScanStatus::sRadioScanRequest();
    m_agents_scan_status_map[ire_mac].single_radio_scans[radio_mac].is_single_scan = true;

    return true;
}

bool dynamic_channel_selection_r2_task::handle_on_demand_channel_selection_request_event(
    const sOnDemandChannelSelectionEvent &channel_selection_event)
{
    const auto &radio_mac      = channel_selection_event.radio_mac;
    const auto channel         = channel_selection_event.channel;
    const auto operating_class = channel_selection_event.operating_class;
    const auto csa_count       = channel_selection_event.csa_count;

    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto agent_mac     = database.get_node_parent_ire(radio_mac_str);
    if (agent_mac == beerocks::net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    if (channel == 0) {
        std::unordered_set<uint8_t> channel_pool_set;
        if (!database.get_selection_channel_pool(radio_mac, channel_pool_set)) {
            LOG(ERROR) << "set_channel_scan_pool failed";
            return false;
        }
        if (!database.set_channel_scan_pool(radio_mac, channel_pool_set, true)) {
            LOG(ERROR) << "set_channel_scan_pool failed";
            return false;
        }
        if (!database.set_channel_scan_dwell_time_msec(radio_mac, 40, true)) {
            LOG(ERROR) << "set_channel_scan_dwell_time_msec failed";
            return false;
        }

        dynamic_channel_selection_r2_task::sSingleScanRequestEvent new_event;
        new_event.radio_mac = radio_mac;
        handle_single_scan_request_event(new_event);

        m_selection_timeout = std::chrono::steady_clock::now() + CHANNEL_SCAN_REPORT_WAIT_TIME;
        FSM_MOVE_SELECTION_STATE(eSelectionState::WAIT_FOR_SCAN);

        m_pending_selection_requests[agent_mac][radio_mac] =
            std::make_shared<sOnDemandAutoChannelSelectionRequest>(channel_pool_set, csa_count);
    } else {
        auto requested_channel = channel;
        if (wireless_utils::is_operating_class_using_central_channel(operating_class)) {
            auto bandwidth         = wireless_utils::operating_class_to_bandwidth(operating_class);
            auto source_channel_it = wireless_utils::channels_table_5g.find(channel);
            if (source_channel_it == wireless_utils::channels_table_5g.end()) {
                LOG(ERROR) << "Couldn't find source channel " << channel
                           << " for overlapping channels";
                return false;
            }
            requested_channel = source_channel_it->second.at(bandwidth).center_channel;
        }

        // Set the selection request for the agent & radio.
        // If doesn't exist unordered_map on set will create a new one.
        // If it does exist, will be overridden as only the latest request should be handled.
        m_pending_selection_requests[agent_mac][radio_mac] =
            std::make_shared<sOnDemandChannelSelectionRequest>(requested_channel, operating_class,
                                                               csa_count);
    }
    return true;
}

bool dynamic_channel_selection_r2_task::handle_preference_request_event(
    const sPreferenceRequestEvent &preference_request_event)
{
    const auto &radio_mac = preference_request_event.radio_mac;

    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto agent_mac     = database.get_node_parent_ire(radio_mac_str);

    if (agent_mac == beerocks::net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    if (m_selection_state != eSelectionState::IDLE) {
        LOG(INFO) << "Cannot send channel preference query because task is not idle";
        return false;
    }

    send_channel_preference_query(agent_mac);
    m_selection_timeout = std::chrono::steady_clock::now() + CHANNEL_PREFERENCE_TIMEOUT;
    FSM_MOVE_SELECTION_STATE(eSelectionState::WAIT_FOR_PREFERENCE);
    return true;
}

bool dynamic_channel_selection_r2_task::handle_continuous_scan_request_event(
    const sContinuousScanRequestStateChangeEvent &scan_request_event)
{
    // Add pending scan request for radio to the task status container
    const auto &radio_mac = scan_request_event.radio_mac;

    // Get parent agent mac from radio mac
    auto radio_mac_str = tlvf::mac_to_string(radio_mac);
    auto agent_mac     = database.get_node_parent_ire(radio_mac_str);
    if (agent_mac == beerocks::net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Failed to get node_parent_ire!";
        return false;
    }

    bool create_new_agent = false;

    // If received "enable" add the continuous radio request (and the agent that manages it if it doesn't exist yet).
    // If received "disable" and the radio is in the agent's status map and not in progress, remove it. If after
    // the removal the agent has no radio scan requests (is empty) then it will also be removed.
    // If continuous radio scan request is in progress then we will not remove it and it will be removed when the scan
    // is complete. Otherwise, do nothing.
    const auto &agent = m_agents_scan_status_map.find(agent_mac);
    if (agent != m_agents_scan_status_map.end()) {
        // Find the scan element within the agent.
        const auto &scan_it = m_agents_scan_status_map[agent_mac].continuous_radio_scans.find(
            scan_request_event.radio_mac);
        // Check if the scan exists
        bool radio_scan_exist = false;
        if (scan_it != m_agents_scan_status_map[agent_mac].continuous_radio_scans.end()) {
            radio_scan_exist = true;
        }

        if (!scan_request_event.enable) {
            // The instruction is to disable the request
            if (!radio_scan_exist) {
                // If we want to disable the scan and the scan does not exist
                // we need to return true as there is no scan to disable.
                return true;
            }

            // If the scan is busy, return false because the scan cannot be disabled.
            if (scan_it->second.status != eRadioScanStatus::PENDING) {
                LOG(WARNING) << "scan is currently waiting for response, will be removed at the "
                                "next response";
                return false;
            }

            // Scan is safe to remove, return true in the end.
            m_agents_scan_status_map[agent_mac].continuous_radio_scans.erase(
                scan_request_event.radio_mac);

            LOG(DEBUG) << "Continuous Radio Scan"
                       << " mac: " << scan_it->first
                       << " was successfully deleted from the container";
            if (m_agents_scan_status_map[agent_mac].single_radio_scans.empty() &&
                m_agents_scan_status_map[agent_mac].continuous_radio_scans.empty()) {
                LOG(TRACE) << "Agent " << agent_mac
                           << " has no remaining scans, removing agent status handler";
                m_agents_scan_status_map.erase(agent);
            }
            return true;
        }
        if (radio_scan_exist) {
            LOG(WARNING) << "A continuous scan on agent: " << agent_mac << " radio: " << radio_mac
                         << " already exists.";
            // If the scan is pending to be triggered, return True.
            // Otherwise the scan is busy (in progress or pending ACK), return False.
            return (scan_it->second.status == eRadioScanStatus::PENDING);
        }
    } else {
        create_new_agent = true;
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
    if (dwell_time_msec < 0) {
        LOG(ERROR) << "continuous_scan cannot proceed without dwell_time value";
        return false;
    }

    // Check if we need to create a new agent handler
    if (create_new_agent) {
        // Add agent to the queue
        m_agents_scan_status_map.insert({agent_mac, {}});
    }

    m_agents_scan_status_map[agent_mac].continuous_radio_scans[radio_mac] =
        sAgentScanStatus::sRadioScanRequest();
    m_agents_scan_status_map[agent_mac].continuous_radio_scans[radio_mac].is_single_scan = false;
    m_agents_scan_status_map[agent_mac].continuous_radio_scans[radio_mac].next_time_scan =
        std::chrono::system_clock::now();

    return true;
}

bool dynamic_channel_selection_r2_task::handle_scan_report_event(
    const sScanReportEvent &scan_report_event)
{
    const auto &agent_mac          = scan_report_event.agent_mac;
    const auto &ISO_8601_timestamp = scan_report_event.ISO_8601_timestamp;

    auto agent_status_it = m_agents_scan_status_map.find(agent_mac);
    if (agent_status_it == m_agents_scan_status_map.end()) {
        LOG(ERROR) << "Agent " << agent_mac << " is not found in active scans";
        return false;
    }
    auto &agent_status = m_agents_scan_status_map[agent_mac];

    auto has_matching_report_index =
        [this, &ISO_8601_timestamp](
            std::pair<sMacAddr, sAgentScanStatus::sRadioScanRequest> const &radio_scan_request_iter)
        -> bool {
        const auto &radio_mac          = radio_scan_request_iter.first;
        const auto &radio_scan_request = radio_scan_request_iter.second;
        auto request_scan_report_copy  = radio_scan_request.scan_report_index;
        node::radio::channel_scan_report_index stored_report_index;
        // Get the report record according to the given timestamp.
        if (!database.get_channel_report_record(radio_mac, ISO_8601_timestamp,
                                                stored_report_index)) {
            LOG(ERROR) << "There is no scan in radio: " << radio_mac
                       << " with timestamp: " << ISO_8601_timestamp;
            return false;
        }
        // Remove the stored_report_key from request_scan_report_copy
        // If an entry is not found that means that the request does not match the report.
        for (const auto &stored_report_key : stored_report_index) {
            if (request_scan_report_copy.erase(stored_report_key) != 1) {
                LOG(DEBUG) << "Request has missing stored report keys: " << stored_report_key.first
                           << "-" << stored_report_key.second;
                return false;
            }
        }
        // If we iterated over the report and all the keys are found in the request and the
        // request is empty, that means the request and report are matching
        if (!request_scan_report_copy.empty()) {
            LOG(DEBUG) << "Stored report does not contain all requested record keys";
            for (const auto &request_report_key : request_scan_report_copy) {
                LOG(DEBUG) << request_report_key.first << "-" << request_report_key.second;
            }
            return false;
        }
        return true;
    };
    sMacAddr radio_mac = beerocks::net::network_utils::ZERO_MAC;
    std::shared_ptr<sAgentScanStatus::sRadioScanRequest> scan_req_ptr(nullptr);
    if (!agent_status.single_radio_scans.empty()) {
        auto radio_scan_it =
            std::find_if(agent_status.single_radio_scans.begin(),
                         agent_status.single_radio_scans.end(), has_matching_report_index);
        if (radio_scan_it == std::end(agent_status.single_radio_scans)) {
            LOG(WARNING) << "No matching scan found in agent's single scans";
        } else {
            radio_mac    = radio_scan_it->first;
            scan_req_ptr = std::make_shared<sAgentScanStatus::sRadioScanRequest>(
                agent_status.single_radio_scans[radio_mac]);
        }
    }
    if (!agent_status.continuous_radio_scans.empty()) {
        auto radio_scan_it =
            std::find_if(agent_status.continuous_radio_scans.begin(),
                         agent_status.continuous_radio_scans.end(), has_matching_report_index);
        if (radio_scan_it == std::end(agent_status.continuous_radio_scans)) {
            LOG(WARNING) << "No matching scan found in agent's continuous scans";
        } else {
            radio_mac    = radio_scan_it->first;
            scan_req_ptr = std::make_shared<sAgentScanStatus::sRadioScanRequest>(
                agent_status.continuous_radio_scans[radio_mac]);
        }
    }

    // If no scan request was found, return with a false result.
    if (!scan_req_ptr) {
        LOG(ERROR) << "No radio scan that matches the received report!";
        return false;
    }

    if (scan_req_ptr->status != eRadioScanStatus::SCAN_IN_PROGRESS) {
        LOG(ERROR) << "The selected scan is not in progress, a report should have not been sent";
        return false;
    }

    /**
     * After a scan's report has been stored validated, need to clear the stored scan request
     * handler. If the scan is a single scan, we can simply remove it from the radio's scan map.
     * If the scan is a continuous scan, we need to check if the scan is still unabled.
     * If the continuous scan is still enabled, we don't delete the scan request handler, but
     * instead set the interval for its next iteration.
     */
    if (!scan_req_ptr->is_single_scan) {
        if (database.get_channel_scan_is_enabled(radio_mac)) {
            LOG(DEBUG) << "Continuous scans on radio " << radio_mac << " are still enabled";
            auto interval = std::chrono::seconds(database.get_channel_scan_interval_sec(radio_mac));
            auto &continuous_scan          = agent_status.continuous_radio_scans[radio_mac];
            continuous_scan.status         = eRadioScanStatus::PENDING;
            continuous_scan.next_time_scan = std::chrono::system_clock::now() + interval;
        } else {
            LOG(DEBUG) << "Removing continuous scan for radio " << radio_mac << " from agent";
            agent_status.continuous_radio_scans.erase(radio_mac);
        }

    } else {
        LOG(DEBUG) << "Removing single scan for radio " << radio_mac << " from agent";
        agent_status.single_radio_scans.erase(radio_mac);
    }
    database.set_channel_scan_in_progress(radio_mac, false, scan_req_ptr->is_single_scan);

    // Remove an empty sAgentScanStatus object
    if (agent_status.single_radio_scans.empty() && agent_status.continuous_radio_scans.empty()) {
        LOG(TRACE) << "Agent " << agent_mac
                   << " has no remaining scans, removing agent status handler";
        m_agents_scan_status_map.erase(agent_status_it);
    } else {
        LOG(TRACE) << "Agent " << agent_mac
                   << " has remaining scans, clearing status but not removing";
        agent_status.status = eAgentStatus::IDLE;
    }

    // Check if On-Demand-Auto is pending
    if (m_selection_state == eSelectionState::WAIT_FOR_SCAN) {
        send_channel_preference_query(agent_mac);
        m_selection_timeout = std::chrono::steady_clock::now() + CHANNEL_PREFERENCE_TIMEOUT;
        FSM_MOVE_SELECTION_STATE(eSelectionState::WAIT_FOR_PREFERENCE);
    }

    return true;
}

bool dynamic_channel_selection_r2_task::send_channel_preference_query(const sMacAddr &agent_mac)
{
    LOG(TRACE) << "Creating CHANNEL_PREFERENCE_QUERY CMDU for agent: " << agent_mac;

    // Build 1905.1 message CMDU to send to the agent.
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CHANNEL_PREFERENCE_QUERY_MESSAGE)) {
        LOG(ERROR) << "CMDU creation of type CHANNEL_PREFERENCE_QUERY_MESSAGE, has failed";
        return false;
    }

    // Send CMDU to agent.
    LOG(INFO) << "Send CHANNEL_PREFERENCE_QUERY_MESSAGE to agent: " << agent_mac;
    if (!son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database)) {
        LOG(ERROR) << "Failed sending message!";
        return false;
    }

    return true;
}

bool dynamic_channel_selection_r2_task::send_selection_requests()
{
    /**
     * The radio-preference-TLV-format container is aligned with the TLV requirements
     * When we want to send the preference TLV we need to sent it in the following container
     * Key:     Pair of Operating-Class & Preference-Score
     * Value:   Set of Channel-Numbers
     */
    using radio_preference_tlv_format = std::map<std::pair<uint8_t, uint8_t>, std::set<uint8_t>>;
    auto convert_preference_report_map_to_tlv_format =
        [](const node::radio::PreferenceReportMap &radio_preference)
        -> radio_preference_tlv_format {
        radio_preference_tlv_format map;
        for (const auto &iter : radio_preference) {
            /*
                Currently the radio's channel preference are build in the following format:
                    Iter: Pair
                        First: Pair
                            First:  Operating Class
                            Second: Channel Number
                        Second: Preference
                But according to the TLV requirements we need to return a map that is
                aligned to the following format:
                    Item:
                        Key: Pair
                            First:  Operating-Class
                            Second: Preference-Score
                        Value:  Set of Channel-Numbers
            */
            map[std::make_pair(iter.first.first, iter.second)].insert(iter.first.second);
        }
        return map;
    };

    auto create_on_demand_channel_preference_tlv =
        [&, this](const sMacAddr &radio_mac,
                  const std::shared_ptr<sOnDemandChannelSelectionRequest> request_details,
                  const radio_preference_tlv_format &formatted_preference) -> bool {
        auto channel_preference_tlv = cmdu_tx.addClass<wfa_map::tlvChannelPreference>();
        if (!channel_preference_tlv) {
            LOG(ERROR) << "addClass ieee1905_1::tlvChannelPreference has failed";
            return false;
        }

        channel_preference_tlv->radio_uid() = radio_mac;

        for (const auto &iter : formatted_preference) {
            const auto operating_class     = iter.first.first;
            const auto reported_preference = iter.first.second;
            const auto &channel_set        = iter.second;

            // If reported preference is In-Operable send it as is, but if it is higher return it as lowest
            // This is so the radio will pick our On-Demand channel all the time
            const auto preference =
                (reported_preference ==
                 (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE)
                    ? (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE
                    : (uint8_t)beerocks::eChannelPreferenceRankingConsts::LOWEST;

            // Create a new channel list without the requested channel
            std::vector<uint8_t> ch_list;
            for (const auto channel_number : channel_set) {
                if (operating_class != request_details->operating_class) {
                    ch_list.push_back(channel_number);
                } else if (channel_number != request_details->channel_number) {
                    ch_list.push_back(channel_number);
                }
                // This is the requested channel, do not add it since it will be added later.
            }
            if (ch_list.empty()) {
                // If the channel list is empty, no need to create an operating class for it.
                // This will only happen if the original channel list contained only the requested channel.
                continue;
            }

            auto operating_classes_list = channel_preference_tlv->create_operating_classes_list();
            operating_classes_list->operating_class()  = operating_class;
            operating_classes_list->flags().preference = preference;
            if (!operating_classes_list->set_channel_list(ch_list.data(), ch_list.size())) {
                LOG(ERROR) << "set_channel_list() failed";
                return false;
            }

            // Push operating class object to the list of operating class objects
            if (!channel_preference_tlv->add_operating_classes_list(operating_classes_list)) {
                LOG(ERROR) << "add_operating_classes_list() has failed!";
                return false;
            }
        }

        return true;
    };

    auto create_on_demand_auto_channel_preference_tlv =
        [&, this](const sMacAddr &radio_mac,
                  const std::shared_ptr<sOnDemandAutoChannelSelectionRequest> request_details,
                  const radio_preference_tlv_format &formatted_preference) -> bool {
        auto channel_preference_tlv = cmdu_tx.addClass<wfa_map::tlvChannelPreference>();
        if (!channel_preference_tlv) {
            LOG(ERROR) << "addClass ieee1905_1::tlvChannelPreference has failed";
            return false;
        }

        channel_preference_tlv->radio_uid() = radio_mac;
        for (const auto &iter : formatted_preference) {
            const auto operating_class     = iter.first.first;
            const auto reported_preference = iter.first.second;
            const auto &channel_set        = iter.second;

            // If reported preference is In-Operable send it as is, but if it is higher return it as lowest
            // This is so the radio will pick our On-Demand channel all the time
            const auto preference =
                (reported_preference ==
                 (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE)
                    ? (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE
                    : (uint8_t)beerocks::eChannelPreferenceRankingConsts::LOWEST;

            // Create a new channel list without the requested channel
            std::vector<uint8_t> ch_list;
            for (const auto channel_number : channel_set) {
                if (request_details->channel_pool.find(channel_number) ==
                    request_details->channel_pool.end()) {
                    ch_list.push_back(channel_number);
                }
                // This is one of the requested channels, do not add it, this will set it's preference as best.
            }
            if (ch_list.empty()) {
                // If the channel list is empty, all of its channels are to be considered as BEST.
                // Skip the channel as this will indicate that the operating class is as considered BEST.
                continue;
            }

            auto operating_classes_list = channel_preference_tlv->create_operating_classes_list();
            operating_classes_list->operating_class()  = operating_class;
            operating_classes_list->flags().preference = preference;
            if (!operating_classes_list->set_channel_list(ch_list.data(), ch_list.size())) {
                LOG(ERROR) << "set_channel_list() failed";
                return false;
            }

            // Push operating class object to the list of operating class objects
            if (!channel_preference_tlv->add_operating_classes_list(operating_classes_list)) {
                LOG(ERROR) << "add_operating_classes_list() has failed!";
                return false;
            }
        }

        return true;
    };

    auto create_channel_preference_tlv =
        [&, this](const sMacAddr &radio_mac,
                  const std::shared_ptr<sChannelSelectionRequest> request_details,
                  const radio_preference_tlv_format &formatted_preference) -> bool {
        auto channel_preference_tlv = cmdu_tx.addClass<wfa_map::tlvChannelPreference>();
        if (!channel_preference_tlv) {
            LOG(ERROR) << "addClass ieee1905_1::tlvChannelPreference has failed";
            return false;
        }

        channel_preference_tlv->radio_uid() = radio_mac;

        for (const auto &iter : formatted_preference) {
            const auto operating_class     = iter.first.first;
            const auto reported_preference = iter.first.second;
            const auto &channel_set        = iter.second;

            // Create a new channel list vector to extract a memory array.
            std::vector<uint8_t> ch_list(channel_set.begin(), channel_set.end());

            auto operating_classes_list = channel_preference_tlv->create_operating_classes_list();
            operating_classes_list->operating_class()  = operating_class;
            operating_classes_list->flags().preference = reported_preference;
            if (!operating_classes_list->set_channel_list(ch_list.data(), ch_list.size())) {
                LOG(ERROR) << "set_channel_list() failed";
                return false;
            }

            // Push operating class object to the list of operating class objects
            if (!channel_preference_tlv->add_operating_classes_list(operating_classes_list)) {
                LOG(ERROR) << "add_operating_classes_list() has failed!";
                return false;
            }
        }
        return true;
    };
    auto create_vs_on_demand_cmdu =
        [&, this](const sMacAddr &radio_mac,
                  const std::shared_ptr<sChannelSelectionRequest> request_details) -> bool {
        // Create channel scan request extended message (vendor specific tlv)
        LOG(INFO) << "Add On-Demand VS-TLV";
        auto on_demand_vs_tlv =
            beerocks::message_com::add_vs_tlv<beerocks_message::tlvVsOnDemandChannelSelection>(
                cmdu_tx);
        if (!on_demand_vs_tlv) {
            LOG(ERROR) << "add_vs_tlv tlvVsOnDemandChannelSelection failed";
            return false;
        }
        on_demand_vs_tlv->radio_mac() = radio_mac;
        on_demand_vs_tlv->CSA_count() = request_details->csa_count;
        return true;
    };

    std::vector<sMacAddr> sent_requests;
    for (const auto &agent_iter : m_pending_selection_requests) {
        const auto &agent_mac = agent_iter.first;
        const auto &agent_map = agent_iter.second;
        // Build 1905.1 message CMDU to send to the agent.
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CHANNEL_SELECTION_REQUEST_MESSAGE)) {
            LOG(ERROR) << "CMDU creation of type CHANNEL_SELECTION_REQUEST_MESSAGE, has failed";
            return false;
        }

        for (const auto &radio_iter : agent_map) {
            const auto &radio_mac        = radio_iter.first;
            const auto request_details   = radio_iter.second;
            const auto &radio_preference = database.get_radio_channel_preference(radio_mac);

            const auto &preference_report =
                convert_preference_report_map_to_tlv_format(radio_preference);

            // If our current request is an On-Demand request
            if (const auto on_demand_details =
                    std::dynamic_pointer_cast<sOnDemandChannelSelectionRequest>(request_details)) {
                // Create Channel-Preference TLV aligned with On-Demand requirements.
                if (!create_on_demand_channel_preference_tlv(radio_mac, on_demand_details,
                                                             preference_report)) {
                    LOG(ERROR) << "Failed to create Channel Preference TLV!";
                    return false;
                }
                // Create channel scan request extended message (vendor specific tlv)
                if (database.is_prplmesh(agent_mac)) {
                    LOG(INFO) << "Agent " << agent_mac << " is prplMesh";
                    if (!create_vs_on_demand_cmdu(radio_mac, request_details)) {
                        LOG(ERROR) << "Failed to create On-Demand VS tlv!";
                        return false;
                    }
                } else {
                    LOG(INFO) << "non-prplmesh agent " << agent_mac
                              << ", skip tlvVsChannelScanRequestExtension creation";
                }
            } else if (const auto on_demand_details =
                           std::dynamic_pointer_cast<sOnDemandAutoChannelSelectionRequest>(
                               request_details)) {
                // Create Channel-Preference TLV aligned with On-Demand-Auto requirements.
                if (!create_on_demand_auto_channel_preference_tlv(radio_mac, on_demand_details,
                                                                  preference_report)) {
                    LOG(ERROR) << "Failed to create Channel Preference TLV!";
                    return false;
                }
                // Create channel scan request extended message (vendor specific tlv)
                if (database.is_prplmesh(agent_mac)) {
                    LOG(INFO) << "Agent " << agent_mac << " is prplMesh";
                    if (!create_vs_on_demand_cmdu(radio_mac, request_details)) {
                        LOG(ERROR) << "Failed to create On-Demand VS tlv!";
                        return false;
                    }
                } else {
                    LOG(INFO) << "non-prplmesh agent " << agent_mac
                              << ", skip tlvVsChannelScanRequestExtension creation";
                }
            } else {
                // Create Channel-Preference TLV.
                if (!create_channel_preference_tlv(radio_mac, request_details, preference_report)) {
                    LOG(ERROR) << "Failed to create Channel Preference TLV!";
                    return false;
                }
            }
        }

        // Send CMDU to agent.
        LOG(INFO) << "Send CHANNEL_SELECTION_REQUEST_MESSAGE to agent: " << agent_mac;
        if (!son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database)) {
            LOG(ERROR) << "Failed sending message!";
            return false;
        }
        sent_requests.push_back(agent_mac);
    }
    for (const auto &agent_mac : sent_requests) {
        m_pending_selection_requests.erase(agent_mac);
    }
    return true;
}

bool dynamic_channel_selection_r2_task::remove_invalid_channel_selection_requests()
{
    std::vector<std::pair<sMacAddr, sMacAddr>> invalid_channel_selection_requests;
    int removed_count = 0;

    for (const auto &agent_iter : m_pending_selection_requests) {
        const auto &agent_mac = agent_iter.first;
        for (const auto &radio_iter : agent_iter.second) {
            const auto &radio_mac = radio_iter.first;

            // Need to check for invalid channel-selection-requests only on On-Demand requests
            if (const auto on_demand_details =
                    std::dynamic_pointer_cast<sOnDemandChannelSelectionRequest>(
                        radio_iter.second)) {
                const auto operating_class = on_demand_details->operating_class;
                const auto channel_number  = on_demand_details->channel_number;
                if (channel_number == 0) {
                    // On-Demand-Auto is always valid, no need to check
                    continue;
                }
                const auto channel_preference = database.get_channel_preference(
                    radio_mac, operating_class, channel_number, true);
                if (channel_preference <= 0) {
                    LOG(ERROR) << "Channel Selection request for channel: " << channel_number
                               << " & operating class: " << operating_class << " is invalid";
                    invalid_channel_selection_requests.push_back(
                        std::make_pair(agent_mac, radio_mac));
                    removed_count++;
                }
            }
        }
    }

    for (const auto &invalid_requests : invalid_channel_selection_requests) {
        const auto &agent_mac = invalid_requests.first;
        const auto &radio_mac = invalid_requests.second;

        const auto &agent_iter = m_pending_selection_requests.find(agent_mac);
        if (agent_iter == m_pending_selection_requests.end()) {
            // Agent does not exist
            continue;
        }
        const auto &radio_iter = agent_iter->second.find(radio_mac);
        if (radio_iter == agent_iter->second.end()) {
            // Radio does not exist
            continue;
        }
        // Erase invalid radio request from pending requests
        agent_iter->second.erase(radio_iter);
        removed_count--;
        if (agent_iter->second.empty()) {
            // Erase empty agent map from pending request
            m_pending_selection_requests.erase(agent_iter);
        }
    }

    // Check if all the elements markeed for removal were removed
    return (removed_count == 0);
}

bool dynamic_channel_selection_r2_task::send_scan_request_to_agent(const sMacAddr &agent_mac)
{
    // Send CMDU to agent
    LOG(INFO) << "Send CHANNEL_SCAN_REQUEST_MESSAGE to agent: " << agent_mac;
    if (!son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database)) {
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
    std::vector<sMacAddr> agents_to_be_deleted;
    for (auto &agent : m_agents_scan_status_map) {
        auto &agent_mac    = agent.first;
        auto &agent_status = agent.second;

        if (!(agent_status.status == eAgentStatus::BUSY &&
              agent_status.timeout <= std::chrono::system_clock::now())) {
            continue;
        }

        timeout_found = true;
        LOG(ERROR) << "Scan request timeout for agent: " << agent_mac
                   << " - aborting in progress scans";

        auto abort_radio_scans = [this, &agent_mac](sAgentScanStatus::RadioScanMap &scan_map,
                                                    const std::string &scan_type) {
            if (scan_map.empty()) {
                LOG(TRACE) << "No " << scan_type << " scans avaliable for agent: " << agent_mac;
                return;
            }
            /**
             * Iterate over the radio scan iterators in the given radio scan map.
             * Abort the "in progress" scans that are present.
             */
            auto scan_it = scan_map.begin();
            while (scan_it != scan_map.end()) {
                auto &radio_mac = scan_it->first;
                auto &radio_req = scan_it->second;
                if (radio_req.status == eRadioScanStatus::PENDING) {
                    // Skip PENDING radio scans, need to abort only active scans
                    scan_it++;
                    continue;
                }
                LOG(ERROR) << "Scan request timeout for radio: " << radio_mac << " - aborting scan";
                database.set_channel_scan_in_progress(radio_mac, false, radio_req.is_single_scan);
                database.set_channel_scan_results_status(
                    radio_mac, beerocks::eChannelScanStatusCode::CHANNEL_SCAN_REPORT_TIMEOUT,
                    radio_req.is_single_scan);

                if (!radio_req.is_single_scan && database.get_channel_scan_is_enabled(radio_mac)) {
                    // If scan type is continuous & scan is enabled, add delay to next iteration but don't remote
                    LOG(ERROR) << "Scan request timeout for radio: " << radio_mac
                               << " - aborting scan and it is delayed by "
                               << INTERVAL_TIME_BETWEEN_RETRIES_ON_FAILURE_SEC / 60 << " minutes.";

                    radio_req.status = eRadioScanStatus::PENDING;
                    radio_req.next_time_scan =
                        std::chrono::system_clock::now() +
                        std::chrono::seconds(INTERVAL_TIME_BETWEEN_RETRIES_ON_FAILURE_SEC);
                    // Move on to next scan iterator
                    scan_it++;
                } else {
                    // Remove from scan list single and disabled scans
                    // Move on to next scan iterator
                    scan_it = scan_map.erase(scan_it);
                }
            }
        };
        abort_radio_scans(agent_status.single_radio_scans, "single");
        abort_radio_scans(agent_status.continuous_radio_scans, "continuous");

        // Clear agent status
        agent_status.status = eAgentStatus::IDLE;
        agents_to_be_deleted.push_back(agent_mac);
    }

    for (const auto &agent_mac : agents_to_be_deleted) {
        m_agents_scan_status_map.erase(agent_mac);
    }

    return timeout_found;
}

bool dynamic_channel_selection_r2_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CHANNEL_PREFERENCE_REPORT_MESSAGE: {
        return handle_cmdu_1905_channel_preference_report(src_mac, cmdu_rx);
    }
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE: {
        return handle_cmdu_1905_channel_selection_response(src_mac, cmdu_rx);
    }
    default:
        return false;
    }
    return true;
}

bool dynamic_channel_selection_r2_task::handle_cmdu_1905_channel_selection_response(
    const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto mid = cmdu_rx.getMessageId();
    LOG(INFO) << "Received CHANNEL_SELECTION_RESPONSE_MESSAGE, mid=" << std::dec << int(mid);

    for (auto channel_selection_response_tlv :
         cmdu_rx.getClassList<wfa_map::tlvChannelSelectionResponse>()) {
        auto &ruid         = channel_selection_response_tlv->radio_uid();
        auto response_code = channel_selection_response_tlv->response_code();

        LOG(DEBUG)
            << "channel selection response from ruid=" << ruid << ", response_code="
            << ([](const wfa_map::tlvChannelSelectionResponse::eResponseCode &response_code) {
                   std::string ret_str;
                   switch (response_code) {
                   case wfa_map::tlvChannelSelectionResponse::eResponseCode::ACCEPT:
                       ret_str.assign("ACCEPT");
                       break;
                   case wfa_map::tlvChannelSelectionResponse::eResponseCode::
                       DECLINE_VIOLATES_CURRENT_PREFERENCES:
                       ret_str.assign("DECLINE_VIOLATES_CURRENT_PREFERENCES");
                       break;
                   case wfa_map::tlvChannelSelectionResponse::eResponseCode::
                       DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES:
                       ret_str.assign("DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES");
                       break;
                   case wfa_map::tlvChannelSelectionResponse::eResponseCode::
                       DECLINE_PREVENT_OPERATION_OF_BACKHAUL_LINK:
                       ret_str.assign("DECLINE_PREVENT_OPERATION_OF_BACKHAUL_LINK");
                       break;
                   default:
                       ret_str.assign("ERROR:UNFAMILIAR_RESPONSE_CODE");
                       break;
                   }
                   return ret_str;
               })(response_code);
    }
    if (m_selection_state == eSelectionState::WAIT_FOR_SELECTION_RESPONSE) {
        FSM_MOVE_SELECTION_STATE(eSelectionState::IDLE);
    }

    return true;
}

bool dynamic_channel_selection_r2_task::handle_cmdu_1905_channel_preference_report(
    const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto mid = cmdu_rx.getMessageId();
    LOG(INFO) << "Received CHANNEL_PREFERENCE_REPORT_MESSAGE, mid=" << std::dec << int(mid);

    auto agent = database.m_agents.get(src_mac);
    if (!agent) {
        LOG(ERROR) << "Agent with mac is not found in database mac=" << src_mac;
        return false;
    }

    // Build ACK message CMDU
    auto cmdu_tx_header = cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return false;
    }
    LOG(DEBUG) << "sending ACK message back to agent";
    son_actions::send_cmdu_to_agent(src_mac, cmdu_tx, database);

    // CHANNEL_PREFERENCE_REPORT_MESSAGE contains zero or more Channel Preference TLVs
    for (const auto &channel_preference_tlv :
         cmdu_rx.getClassList<wfa_map::tlvChannelPreference>()) {

        if (!handle_tlv_channel_preference(channel_preference_tlv)) {
            LOG(ERROR) << "Failed to parse the Channel Preference TLV";
            return false;
        }
    }

    // CHANNEL_PREFERENCE_REPORT_MESSAGE contains zero or more Radio Operation Restriction TLVs
    for (const auto &radio_operation_restriction_tlv :
         cmdu_rx.getClassList<wfa_map::tlvRadioOperationRestriction>()) {

        if (!handle_tlv_radio_operation_restriction(radio_operation_restriction_tlv)) {
            LOG(ERROR) << "Failed to parse the Radio Operation Restriction TLV";
            return false;
        }
    }

    if (agent->profile > wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::MULTIAP_PROFILE_1) {

        // CHANNEL_PREFERENCE_REPORT_MESSAGE contains zero or one CAC Completion Report TLV
        auto cac_completion_report_tlv =
            cmdu_rx.getClass<wfa_map::tlvProfile2CacCompletionReport>();
        if (!cac_completion_report_tlv) {
            // There is no tlvProfile2CacCompletionReport present, send a warning, but continue normally.
            LOG(INFO) << "Profile2 CAC Completion Report is not supplied for Agent " << src_mac
                      << " with profile enum " << agent->profile;
        } else if (!handle_tlv_profile2_cac_completion_report(cac_completion_report_tlv)) {
            LOG(ERROR) << "Failed to parse Profile2 CAC Completion Report";
            return false;
        }

        // CHANNEL_PREFERENCE_REPORT_MESSAGE contains one CAC Status Report TLV
        auto cac_status_report_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2CacStatusReport>();
        if (!cac_status_report_tlv) {
            LOG(ERROR) << "Profile2 CAC Status Report is not supplied for Agent " << src_mac
                       << " with profile enum " << agent->profile;
            return false;
        } else if (!handle_tlv_profile2_cac_status_report(agent, cac_status_report_tlv)) {
            LOG(ERROR) << "Failed to parse Profile2 CAC Status Report";
            return false;
        }
    }

    if (m_selection_state == eSelectionState::WAIT_FOR_PREFERENCE) {
        FSM_MOVE_SELECTION_STATE(eSelectionState::IDLE);
    }
    return true;
}

bool dynamic_channel_selection_r2_task::handle_tlv_channel_preference(
    const std::shared_ptr<wfa_map::tlvChannelPreference> &channel_preference_tlv)
{
    std::stringstream ss;

    const auto &radio_uid = channel_preference_tlv->radio_uid();
    auto radio            = database.get_radio_by_uid(radio_uid);
    if (!radio) {
        LOG(ERROR) << "Failed to get Radio Object with uid: " << radio_uid;
        return false;
    }

    database.clear_channel_preference(radio_uid);
    ss << "Preference for radio " << radio_uid << ":" << std::endl;
    for (size_t i = 0; i < channel_preference_tlv->operating_classes_list_length(); i++) {
        if (!std::get<0>(channel_preference_tlv->operating_classes_list(i))) {
            LOG(ERROR) << "Invalid operating class in tlvChannelPreference";
            continue;
        }
        auto &operating_class    = std::get<1>(channel_preference_tlv->operating_classes_list(i));
        const auto &op_cls_num   = operating_class.operating_class();
        const auto &op_cls_flags = operating_class.flags();

        ss << "Operating Class: #" << int(op_cls_num) << ", ";
        ss << "Flag, preference: " << int(op_cls_flags.preference) << ", ";
        ss << "Flag, reason code: " << int(op_cls_flags.reason_code) << std::endl;

        std::set<uint8_t> channel_set;
        if (operating_class.channel_list_length() == 0) {
            // An empty Channel List field indicates that the indicated
            // Preference applies to all channels in the Operating Class.
            const auto all_channels_in_operating_class =
                wireless_utils::operating_class_to_channel_set(op_cls_num);
            channel_set.insert(all_channels_in_operating_class.begin(),
                               all_channels_in_operating_class.end());
        } else {
            for (size_t j = 0; j < operating_class.channel_list_length(); j++) {
                const auto channel = operating_class.channel_list(j);
                if (!channel) {
                    LOG(ERROR) << "getting channel entry has failed!";
                    continue;
                }
                channel_set.insert(*channel);
            }

            ss << "Channel list: [";
            for (const auto channel_num : channel_set) {
                ss << int(channel_num) << " ";
                if (!database.set_channel_preference(radio_uid, op_cls_num, channel_num,
                                                     op_cls_flags.preference)) {
                    LOG(ERROR) << "Failed to update Channel Preference";
                    return false;
                }
            }
            ss << "]." << std::endl;
        }
    }

    LOG(INFO) << ss.str();
    return true;
}

bool dynamic_channel_selection_r2_task::handle_tlv_radio_operation_restriction(
    const std::shared_ptr<wfa_map::tlvRadioOperationRestriction> &radio_operation_restriction_tlv)
{
    // Currently there is no handling for the radio operation restrictions.
    // TODO - PPM-2042: Parse the Radio Operation Restriction TLVs.

    return true;
}

bool dynamic_channel_selection_r2_task::handle_tlv_profile2_cac_completion_report(
    const std::shared_ptr<wfa_map::tlvProfile2CacCompletionReport> &cac_completion_report_tlv)
{
    LOG(DEBUG) << "Profile-2 CAC Completion Report is received";
    // Currently there is no handling for the cac completion report.
    // TODO - PPM-1524: Parse the CAC Completion Report TLV.

    return true;
}

bool dynamic_channel_selection_r2_task::handle_tlv_profile2_cac_status_report(
    const std::shared_ptr<Agent> agent,
    const std::shared_ptr<wfa_map::tlvProfile2CacStatusReport> &cac_status_report_tlv)
{
    LOG(DEBUG) << "Profile-2 CAC Status Report is received";

    database.dm_clear_cac_status_report(agent);
    std::stringstream ss;

    for (size_t i = 0; i < cac_status_report_tlv->number_of_available_channels(); i++) {

        if (!std::get<0>(cac_status_report_tlv->available_channels(i))) {
            LOG(ERROR) << "Invalid available-channel in tlvProfile2CacStatusReport";
            continue;
        }

        const auto &available_channel = std::get<1>(cac_status_report_tlv->available_channels(i));
        database.dm_add_cac_status_available_channel(agent, available_channel.operating_class,
                                                     available_channel.channel);
        ss << "[Ch:" << available_channel.channel << ",OC:" << available_channel.operating_class
           << "] ";
    }
    LOG(DEBUG) << ss.str();
    return true;
}

bool dynamic_channel_selection_r2_task::handle_timeout_in_selection_flow()
{
    if (m_selection_state != eSelectionState::SELECTION_ABORTED) {
        return true;
    }

    m_pending_selection_requests.clear();
    FSM_MOVE_SELECTION_STATE(eSelectionState::IDLE);
    return true;
}
