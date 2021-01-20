/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "channel_scan_task.h"
#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager.h"
#include <bcl/beerocks_utils.h>
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <beerocks/tlvf/beerocks_message_backhaul.h>
#include <easylogging++.h>
#include <tlvf/wfa_map/tlvTunnelledSourceInfo.h>

using namespace beerocks;

#define FSM_MOVE_STATE(radio_scan_info, new_state)                                                 \
    ({                                                                                             \
        LOG(TRACE) << "CHANNEL_SCAN " << radio_scan_info->radio_mac                                \
                   << " FSM: " << m_states_string.at(radio_scan_info->current_state) << " --> "    \
                   << m_states_string.at(new_state);                                               \
        radio_scan_info->current_state = new_state;                                                \
    })

/**
 * ToDo: Remove this "default" parameter after PPM-747 is resolved.
 */
constexpr unsigned int PREFERRED_DWELLTIME_MS          = 40;  // 40 Millisec
constexpr unsigned int SCAN_TRIGGERED_WAIT_TIME_SEC    = 20;  // 20 Sec
constexpr unsigned int SCAN_RESULTS_DUMP_WAIT_TIME_SEC = 210; // 3.5 Min

ChannelScanTask::ChannelScanTask(BackhaulManager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SCAN), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ChannelScanTask::work()
{
    // Handle currently running scan.
    if (m_current_scan_info.is_scan_currently_running) {
        auto current_scan_request = m_current_scan_info.scan_request;
        auto current_radio_scan   = m_current_scan_info.radio_scan;

        // Handle current radio-scan's state
        switch (current_radio_scan->current_state) {
        case eState::PENDING_TRIGGER: {
            // Wait until Current-Scan resource is free.
            break;
        }
        case eState::WAIT_FOR_SCAN_TRIGGERED: {
            if (current_radio_scan->timeout < std::chrono::system_clock::now()) {
                LOG(ERROR) << "Reached timeout for PENDING_TRIGGER";
                FSM_MOVE_STATE(current_radio_scan, eState::SCAN_FAILED);
            }
            break;
        }
        case eState::WAIT_FOR_RESULTS_READY: {
            if (current_radio_scan->timeout < std::chrono::system_clock::now()) {
                LOG(ERROR) << "Reached timeout for WAIT_FOR_RESULTS_READY";
                FSM_MOVE_STATE(current_radio_scan, eState::SCAN_FAILED);
            }
            break;
        }
        case eState::WAIT_FOR_RESULTS_DUMP: {
            if (current_radio_scan->timeout < std::chrono::system_clock::now()) {
                LOG(ERROR) << "Reached timeout for WAIT_FOR_RESULTS_DUMP";
                FSM_MOVE_STATE(current_radio_scan, eState::SCAN_FAILED);
            }
            break;
        }
        case eState::SCAN_DONE: {
            if (!is_scan_request_finished(current_scan_request)) {
                LOG(INFO) << "Wait for other scans to complete";
                trigger_next_radio_scan(current_scan_request);
            } else {
                current_scan_request->ready_to_send_report = true;
            }
            break;
        }
        case eState::SCAN_FAILED: {
            if (!is_scan_request_finished(current_scan_request)) {
                LOG(INFO) << "Wait for other scans to complete";
                trigger_next_radio_scan(current_scan_request);
            } else {
                current_scan_request->ready_to_send_report = true;
            }
            break;
        }
        case eState::SCAN_ABORTED: {
        }
        default:
            break;
        }

        // Handle finished requests.
        if (current_scan_request->ready_to_send_report) {
            m_current_scan_info.is_scan_currently_running = false;
            if (!send_channel_scan_report(current_scan_request)) {
                LOG(ERROR) << "Failed to send channel scan report!";
                return;
            }
        }
    } else {
        // Handle pending requests.
        if (!m_pending_requests.empty()) {
            if (!trigger_next_radio_scan(m_pending_requests.front())) {
                LOG(ERROR) << "Failed to trigger the radio scan on top request in queue";
            }
            m_pending_requests.pop_front();
        }
    }
}

void ChannelScanTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    case eEvent::INDEPENDENT_SCAN_REQUEST: {
        auto scan_event = reinterpret_cast<const sScanRequestEvent *>(event_obj);
        LOG(TRACE) << "Received SCAN_TRIGGERED event";
        (void)scan_event;
        break;
    }
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ChannelScanTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                                  const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                                  std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CHANNEL_SCAN_REQUEST_MESSAGE: {
        return handle_channel_scan_request(cmdu_rx, src_mac);
    }
    case ieee1905_1::eMessageType::VENDOR_SPECIFIC_MESSAGE: {
        return handle_vendor_specific(cmdu_rx, src_mac, fd, beerocks_header);
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

bool ChannelScanTask::handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx,
                                             const sMacAddr &src_mac, int fd,
                                             std::shared_ptr<beerocks_header> beerocks_header)
{
    if (!beerocks_header) {
        LOG(ERROR) << "beerocks_header is nullptr";
        return false;
    }

    auto is_current_scan_running = [this]() -> bool {
        if (!m_current_scan_info.is_scan_currently_running) {
            LOG(ERROR) << "No scan is currently running";
            return false;
        }
        return true;
    };
    auto does_current_scan_match_incoming_src = [this](const sMacAddr &src_mac) -> bool {
        if (m_current_scan_info.radio_scan->radio_mac != src_mac) {
            LOG(ERROR) << "Currently running scan radio MAC does not match incoming response's. "
                       << m_current_scan_info.radio_scan->radio_mac << " != " << src_mac;
            return false;
        }
        return true;
    };
    auto is_current_scan_in_state = [this](eState scan_expected_state) -> bool {
        if (m_current_scan_info.radio_scan->current_state != scan_expected_state) {
            LOG(ERROR) << "Currently running scan is not in "
                       << m_states_string.at(scan_expected_state)
                       << " state, current scan is in state: "
                       << m_states_string.at(m_current_scan_info.radio_scan->current_state);
            return false;
        }
        return true;
    };

    /**
     * Since currently we handle only action_ops of action type "ACTION_BACKHAUL", use a single
     * switch-case on "ACTION_BACKHAUL" only.
     * Once the son_slave will be unified, need to replace the expected action to "ACTION_MONITOR".
     * PPM-352.
     */
    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE from mac " << src_mac;
        auto response =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE>();
        if (!response) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE failed";
            return false;
        }

        if (!is_current_scan_running() || !does_current_scan_match_incoming_src(src_mac) ||
            !is_current_scan_in_state(eState::WAIT_FOR_SCAN_TRIGGERED)) {
            return false;
        }

        if (!response->success()) {
            LOG(ERROR) << "Failed to trigger scan on radio (" << src_mac << ")";
            FSM_MOVE_STATE(m_current_scan_info.radio_scan, eState::SCAN_FAILED);
            return true;
        }

        LOG(INFO) << "scan request was successful for radio (" << src_mac
                  << "). Wait for SCAN_TRIGGERED notification";
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION from mac " << src_mac;
        auto notification = beerocks_header->addClass<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION>();
        if (!notification) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION failed";
            return false;
        }

        if (!is_current_scan_running() || !does_current_scan_match_incoming_src(src_mac) ||
            !is_current_scan_in_state(eState::WAIT_FOR_SCAN_TRIGGERED)) {
            return false;
        }

        LOG(INFO) << "Scan was triggered successfully, wait for RESULTS_READY_NOTIFICATION.";
        FSM_MOVE_STATE(m_current_scan_info.radio_scan, eState::WAIT_FOR_RESULTS_READY);

        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_RESULTS_NOTIFICATION: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_RESULTS_NOTIFICATION from mac " << src_mac;
        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_RESULTS_NOTIFICATION>();
        if (!notification) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_RESULTS_NOTIFICATION failed";
            return false;
        }

        if (!is_current_scan_running() || !does_current_scan_match_incoming_src(src_mac)) {
            return false;
        }

        if (notification->is_dump() == 0) {
            if (!is_current_scan_in_state(eState::WAIT_FOR_RESULTS_READY)) {
                LOG(INFO) << "Scan results are ready, wait for RESULTS_DUMP_NOTIFICATION.";
                FSM_MOVE_STATE(m_current_scan_info.radio_scan, eState::WAIT_FOR_RESULTS_DUMP);
            }
            // Todo
        } else {
            if (!is_current_scan_in_state(eState::WAIT_FOR_RESULTS_DUMP)) {
                return false;
            }
            if (!store_radio_scan_result(m_current_scan_info.scan_request, src_mac,
                                         notification->scan_results())) {
                LOG(ERROR) << "Failed to store radio scan result!";
                return false;
            }
            LOG(INFO) << "Scan result received, wait for another RESULTS_DUMP_NOTIFICATION or "
                         "SCAN_FINISHED_NOTIFICATION.";
            FSM_MOVE_STATE(m_current_scan_info.radio_scan, eState::WAIT_FOR_RESULTS_DUMP);
        }
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_FINISHED_NOTIFICATION: {
        LOG(DEBUG) << "ACTION_BACKHAUL_CHANNEL_SCAN_FINISHED_NOTIFICATION from mac " << src_mac;
        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_FINISHED_NOTIFICATION>();
        if (!notification) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_FINISHED_NOTIFICATION failed";
            return false;
        }

        if (!is_current_scan_running() || !does_current_scan_match_incoming_src(src_mac) ||
            !is_current_scan_in_state(eState::WAIT_FOR_RESULTS_DUMP)) {
            return false;
        }

        auto radio = AgentDB::get()->get_radio_by_mac(src_mac);
        if (!radio) {
            return false;
        }
        radio->statuses.channel_scan_in_progress = false;
        FSM_MOVE_STATE(m_current_scan_info.radio_scan, eState::SCAN_DONE);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_ABORTED_NOTIFICATION: {
        LOG(DEBUG) << "ACTION_BACKHAUL_CHANNEL_SCAN_ABORTED_NOTIFICATION from mac " << src_mac;

        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_ABORTED_NOTIFICATION>();
        if (!notification) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_ABORTED_NOTIFICATION failed";
            return false;
        }

        if (!is_current_scan_running() || !does_current_scan_match_incoming_src(src_mac)) {
            return false;
        }

        auto radio = AgentDB::get()->get_radio_by_mac(src_mac);
        if (!radio) {
            break;
        }
        radio->statuses.channel_scan_in_progress = false;
        FSM_MOVE_STATE(m_current_scan_info.radio_scan, eState::SCAN_ABORTED);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE from mac " << src_mac;
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_ABORT_RESPONSE: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_ABORT_RESPONSE from mac " << src_mac;
        break;
    }
    default: {
        // Message was not handled, therfore return false.
        return false;
    }
    }
    return true;
}

/* Helper functions */

bool ChannelScanTask::is_scan_request_finished(const std::shared_ptr<sScanRequest> request)
{
    auto radio_scans = request->radio_scans;
    auto radio_scan_not_finished =
        [](std::pair<std::string, std::shared_ptr<sRadioScan>> radio_scan_iter) -> bool {
        return radio_scan_iter.second->current_state != eState::SCAN_DONE &&
               radio_scan_iter.second->current_state != eState::SCAN_FAILED;
    };
    auto unfinished_radio_scan_in_request =
        std::find_if(radio_scans.begin(), radio_scans.end(), radio_scan_not_finished);

    // Returns "True" if no unfinished scans were found
    return unfinished_radio_scan_in_request == radio_scans.end();
}

bool ChannelScanTask::abort_scan_request(const std::shared_ptr<sScanRequest> request)
{
    for (auto radio_scan : request->radio_scans) {
        const auto &radio_iface = radio_scan.first;
        LOG(TRACE) << "Request scan abort on " << radio_iface;

        auto fronthaul_sd = m_btl_ctx.front_iface_name_to_socket(radio_iface);
        if (fronthaul_sd == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(DEBUG) << "socket to fronthaul not found: " << radio_iface;
            return false;
        }

        auto abort_request = beerocks::message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST>(m_cmdu_tx);
        if (!abort_request) {
            LOG(ERROR) << "Failed to build cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST";
            return false;
        }

        if (!m_btl_ctx.send_cmdu(fronthaul_sd, m_cmdu_tx)) {
            LOG(ERROR) << "Failed to send cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST for "
                       << radio_iface;
            return false;
        }

        LOG(TRACE) << "Sent ABORT_CHANNEL_SCAN for radio " << radio_iface;
    }

    return true;
}

bool ChannelScanTask::trigger_next_radio_scan(const std::shared_ptr<sScanRequest> request)
{
    /**
     * Currently only one Channel Scan per radio is supported.
     * When PPM-711 is resolved we need to rework the trigger mechanism to support multiple
     * simultaneous radio scans.
     * https://jira.prplfoundation.org/browse/PPM-711
     */
    auto &radio_scans = request->radio_scans;
    auto radio_scan_is_pending =
        [](std::pair<std::string, std::shared_ptr<sRadioScan>> radio_scan_iter) -> bool {
        return radio_scan_iter.second->current_state == eState::PENDING_TRIGGER;
    };
    auto next_pending_radio_scan =
        std::find_if(radio_scans.begin(), radio_scans.end(), radio_scan_is_pending);
    if (next_pending_radio_scan == radio_scans.end()) {
        LOG(TRACE) << "Unable to find the next pending radio scan in request.";
        return false;
    }
    if (!trigger_radio_scan(next_pending_radio_scan->first, next_pending_radio_scan->second)) {
        LOG(ERROR) << "Failed to send radio scan trigger request";
        return false;
    }

    m_current_scan_info.scan_request              = request;
    m_current_scan_info.radio_scan                = next_pending_radio_scan->second;
    m_current_scan_info.is_scan_currently_running = true;

    return true;
}

bool ChannelScanTask::trigger_radio_scan(const std::string &radio_iface,
                                         const std::shared_ptr<sRadioScan> radio_scan_info)
{
    auto fronthaul_sd = m_btl_ctx.front_iface_name_to_socket(radio_iface);
    if (fronthaul_sd == beerocks::net::FileDescriptor::invalid_descriptor) {
        LOG(DEBUG) << "socket to fronthaul not found: " << radio_iface;
        return false;
    }
    auto radio = AgentDB::get()->radio(radio_iface);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio info from Agent DB for " << radio_iface;
        return false;
    }

    auto trigger_request = beerocks::message_com::create_vs_message<
        beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST>(m_cmdu_tx);
    if (!trigger_request) {
        LOG(ERROR) << "Failed to build cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST";
        return false;
    }

    /**
     * Copy the channel list within the operating class vector in the found Radio Scan info.
     * Using an unordered_set since we do not want duplicated channels in out channel pool
     */
    std::unordered_set<uint8_t> channels_to_be_scanned;
    std::for_each(radio_scan_info->operating_classes.begin(),
                  radio_scan_info->operating_classes.end(),
                  [&channels_to_be_scanned](const sOperationalClass &op_cls) {
                      channels_to_be_scanned.insert(std::begin(op_cls.channel_list),
                                                    std::end(op_cls.channel_list));
                  });
    // Set scan params in CMDU
    trigger_request->scan_params().radio_mac         = radio_scan_info->radio_mac;
    trigger_request->scan_params().dwell_time_ms     = PREFERRED_DWELLTIME_MS;
    trigger_request->scan_params().channel_pool_size = channels_to_be_scanned.size();
    std::copy(channels_to_be_scanned.begin(), channels_to_be_scanned.end(),
              trigger_request->scan_params().channel_pool);

    // Print CMDU scan parameters
    auto print_pool = [](uint8_t *pool, uint8_t size) -> std::string {
        std::stringstream ss;
        ss << "[ ";
        for (int ch_idx = 0; ch_idx < size; ch_idx++) {
            ss << int(pool[ch_idx]) << " ";
        }
        ss << "]";
        return ss.str();
    };
    LOG(DEBUG) << "Sending \"Scan Trigger\" request for the following:" << std::endl
               << "- Radio MAC: " << trigger_request->scan_params().radio_mac << std::endl
               << "- Dwell time: " << trigger_request->scan_params().dwell_time_ms << std::endl
               << "- Channels: "
               << print_pool(trigger_request->scan_params().channel_pool,
                             trigger_request->scan_params().channel_pool_size);

    // Send CMDU
    return m_btl_ctx.send_cmdu(fronthaul_sd, m_cmdu_tx);
}

bool ChannelScanTask::store_radio_scan_result(const std::shared_ptr<sScanRequest> request,
                                              const sMacAddr &radio_mac,
                                              beerocks_message::sChannelScanResults results)
{
    LOG(TRACE) << "Handling scan result from " << radio_mac;
    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio info from Agent DB for " << radio_mac;
        return false;
    }

    auto channel_scan_results_iter = radio->channel_scan_results.find(results.channel);
    if (channel_scan_results_iter != radio->channel_scan_results.end()) {
        // Previous results are found for the given channel.
        auto &channel_scan_results = channel_scan_results_iter->second;
        // channel_scan_results: pair<system_clock::time_point, vector<sChannelScanResults>>
        //      First:  Scan results timestamp
        //      Second: Scan results vector
        if (channel_scan_results.first < request->scan_start_timestamp) {
            // The currently stored channel scan results are older then the incoming results and
            // are to be considered aged/invalid.
            // Reset currently stored channel scan results.
            channel_scan_results.first = request->scan_start_timestamp;
            channel_scan_results.second.clear();
        }
    }
    radio->channel_scan_results[results.channel].second.push_back(results);
    return true;
}

bool ChannelScanTask::handle_channel_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac)
{
    const auto scan_start_timestamp = std::chrono::system_clock::now();
    const auto mid                  = cmdu_rx.getMessageId();

    auto channel_scan_request_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2ChannelScanRequest>();
    if (!channel_scan_request_tlv) {
        LOG(ERROR) << "getClass wfa_map::tlvProfile2ChannelScanRequest failed";
        return false;
    }

    const auto &perform_fresh_scan = channel_scan_request_tlv->perform_fresh_scan();

    LOG(INFO) << "Received CHANNEL_SCAN_REQUEST_MESSAGE from "
              << "radio MAC: " << src_mac << " mid: " << std::hex << mid << "." << std::endl
              << "The perform_fresh_scan flag set to: \""
              << (perform_fresh_scan == wfa_map::tlvProfile2ChannelScanRequest::ePerformFreshScan::
                                            PERFORM_A_FRESH_SCAN_AND_RETURN_RESULTS
                      ? "PERFORM_A_FRESH_SCAN_AND_RETURN_RESULTS"
                      : "RETURN_STORED_RESULTS_OF_LAST_SUCCESSFUL_SCAN")
              << "\"";

    // Build and send ACK message CMDU to the originator.
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return false;
    }

    LOG(DEBUG) << "Sending ACK message to the originator, mid=" << std::hex << mid;
    auto db = AgentDB::get();
    if (!m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, db->bridge.mac)) {
        LOG(ERROR) << "Failed to send ACK_MESSAGE back to controller";
        return false;
    }

    if (perform_fresh_scan && m_current_scan_info.is_scan_currently_running) {
        // Check if current scan can be aborted.
        auto current_request_info = m_current_scan_info.scan_request;
        // Only Controller-Requested scan requests can be aborted.
        if (current_request_info->request_info->request_type ==
            sRequestInfo::eScanRequestType::ControllerRequested) {
            if (!abort_scan_request(current_request_info)) {
                LOG(ERROR) << "Failed to abort current scan request!";
                return false;
            }
        }
    }

    sControllerRequestInfo request_info;
    request_info.mid                = mid;
    request_info.src_mac            = src_mac;
    request_info.perform_fresh_scan = perform_fresh_scan;

    auto new_request = std::shared_ptr<sScanRequest>(new sScanRequest(), [](sScanRequest *ptr) {
        LOG(TRACE) << "Deleting scan request: " << std::hex << ptr << ".";
        delete ptr;
    });
    new_request->request_info         = std::make_shared<sControllerRequestInfo>(request_info);
    new_request->scan_start_timestamp = scan_start_timestamp;
    new_request->ready_to_send_report = false;

    const auto &radio_list_length = channel_scan_request_tlv->radio_list_length();
    // Iterate over the incoming radio list
    for (int radio_i = 0; radio_i < radio_list_length; ++radio_i) {
        const auto &radio_list_tuple = channel_scan_request_tlv->radio_list(radio_i);
        if (!std::get<0>(radio_list_tuple)) {
            LOG(ERROR) << "Failed to get radio_list[" << radio_i << "]. Continuing...";
            continue;
        }
        auto &radio_list_entry     = std::get<1>(radio_list_tuple);
        const auto radio_mac       = radio_list_entry.radio_uid();
        const auto op_cls_list_len = radio_list_entry.operating_classes_list_length();
        if (op_cls_list_len == 0 && perform_fresh_scan) {
            LOG(ERROR) << "Invalid request! A fresh scan was requested, but no operating classed "
                          "were sent";
            return false;
        }
        const auto radio = db->get_radio_by_mac(radio_mac);
        if (!radio) {
            LOG(ERROR) << "Failed to get radio entry for MAC: " << radio_mac;
            return false;
        }
        const auto radio_iface = radio->front.iface_name;

        LOG(TRACE) << "radio_list[" << radio_i << "]:" << std::endl
                   << "\tRadio iface: " << radio_iface << std::endl
                   << "\tRadio MAC: " << radio_mac << std::endl
                   << "\tOperating class list length:" << int(op_cls_list_len);

        // Create new radio scan
        auto new_radio_scan = std::shared_ptr<sRadioScan>(new sRadioScan(), [](sRadioScan *ptr) {
            LOG(TRACE) << "Deleting radio scan: " << std::hex << ptr << ".";
            delete ptr;
        });
        new_radio_scan->radio_mac     = radio_mac;
        new_radio_scan->current_state = eState::PENDING_TRIGGER;

        // Iterate over operating classes
        for (int op_cls_idx = 0; op_cls_idx < op_cls_list_len; op_cls_idx++) {
            const auto &op_cls_tuple = radio_list_entry.operating_classes_list(op_cls_idx);
            if (!std::get<0>(op_cls_tuple)) {
                LOG(ERROR) << "Failed to get operating class[" << op_cls_idx << "]. Continuing...";
                continue;
            }

            auto &op_cls_entry    = std::get<1>(op_cls_tuple);
            const auto op_cls_num = op_cls_entry.operating_class();
            const auto ch_lst_len = op_cls_entry.channel_list_length();
            const auto ch_lst_arr = op_cls_entry.channel_list();

            std::stringstream ss;
            ss << "[ ";
            for (int c_idx = 0; c_idx < ch_lst_len; c_idx++) {
                ss << int(ch_lst_arr[c_idx]) << " ";
            }
            ss << "]";
            LOG(TRACE) << "Operating class[" << op_cls_idx << "]:" << std::endl
                       << "\tOperating class : #" << int(op_cls_num) << std::endl
                       << "\tChannel list length:" << int(ch_lst_len) << std::endl
                       << "\tChannel list: " << ss.str() << ".";

            new_radio_scan->operating_classes.emplace_back(op_cls_num, ch_lst_arr, ch_lst_len);
        }

        // Add radio scan info to radio scans map in the request
        new_request->radio_scans.emplace(radio_iface, new_radio_scan);
    }

    // Should return all the currently stored results in the DB for the requested radios
    // There is no need to add it to the request queue, since there is no need to perform a scan.
    if (!perform_fresh_scan) {
        new_request->ready_to_send_report = true;
        return send_channel_scan_report_to_controller(new_request);
    }
    m_pending_requests.emplace_back(new_request);
    return true;
}

bool ChannelScanTask::send_channel_scan_report(const std::shared_ptr<sScanRequest> request)
{
    const auto request_info = request->request_info;
    switch (request_info->request_type) {
    case sRequestInfo::eScanRequestType::ControllerRequested: {
        return send_channel_scan_report_to_controller(request);
    }
    default: {
        LOG(ERROR) << "Request of unknown type!";
        return false;
    }
    }
}

bool ChannelScanTask::send_channel_scan_report_to_controller(
    const std::shared_ptr<sScanRequest> request)
{
    // Lambda function that fills the TLV neighbor structure.
    auto fill_scan_result_tlv_with_neighbors =
        [](const beerocks_message::sChannelScanResults &neighbor,
           std::shared_ptr<wfa_map::cNeighbors> neighbor_res) -> bool {
        // BSSID
        neighbor_res->bssid() = neighbor.bssid;

        // SSID
        if (!neighbor_res->set_ssid(neighbor.ssid, std::string(neighbor.ssid).length())) {
            LOG(ERROR) << "Failed to set SSID";
            return false;
        }

        // Signal Strength
        neighbor_res->signal_strength() = neighbor.signal_strength_dBm;

        // Bandwidth
        auto eChannelScanResultChannelBandwidth_toString =
            [](const beerocks_message::eChannelScanResultChannelBandwidth &bw) -> std::string {
            switch (bw) {
            case beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_20MHz:
                return "20";
            case beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_40MHz:
                return "40";
            case beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80MHz:
                return "80";
            case beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80_80:
                return "80+80";
            case beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_160MHz:
                return "160";
            case beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_NA:
            default:
                return "";
            }
        };
        auto bw_str =
            eChannelScanResultChannelBandwidth_toString(neighbor.operating_channel_bandwidth);
        if (!neighbor_res->set_channels_bw_list(bw_str.c_str(), bw_str.length())) {
            LOG(ERROR) << "Failed to set channel BW list";
            return false;
        }

        // BSS Load Element Present
        // Resolve as part of PPM-1045
        neighbor_res->bss_load_element_present() =
            wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_NOT_PRESENT;

        // Channel Utilization
        // Resolve as part of PPM-1045
        // Since BSS Load Element Present is set to "Not Present" no need to set  Channel Utilization.
        // neighbor_res->channel_utilization() = neighbor.channel_utilization;

        // Station Count
        // Resolve as part of PPM-1045
        // Since BSS Load Element Present is set to "Not Present" no need to set Station Count.
        // neighbor_res->station_count() = 0;

        LOG(TRACE) << "Done filling report structure";
        return true;
    };

    // Lambda function that creates the Timestamp TLV.
    auto add_report_timestamp_tlv = [this](const std::string &timestamp) -> bool {
        LOG(DEBUG) << "Creating tlvTimestamp";

        // add Timestamp TLV
        auto timestamp_tlv = m_cmdu_tx.addClass<wfa_map::tlvTimestamp>();
        if (!timestamp_tlv) {
            LOG(ERROR) << "addClass tlvTimestamp failed";
            return false;
        }
        LOG(TRACE) << "timestamp tlv created";

        // fill Timestamp TLV
        if (!timestamp_tlv->set_timestamp(timestamp.c_str(), timestamp.size())) {
            LOG(ERROR) << "Failed to set timestamp in tlvTimestamp!";
            return false;
        }
        return true;
    };

    // Lambda function that creates the Scan Report TLV.
    auto add_scan_result_tlv =
        [this, &fill_scan_result_tlv_with_neighbors](
            const sMacAddr &ruid, const uint8_t &operating_class, const uint8_t &channel,
            wfa_map::tlvProfile2ChannelScanResult::eScanStatus scan_status,
            std::chrono::system_clock::time_point scan_start_time,
            std::vector<beerocks_message::sChannelScanResults> neighbors) -> bool {
        LOG(DEBUG) << "Creating Scan-Result TLV";
        // add Results TLV
        auto channel_scan_result_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2ChannelScanResult>();
        if (!channel_scan_result_tlv) {
            LOG(ERROR) << "addClass tlvProfile2ChannelScanResult failed";
            return false;
        }

        // fill Results TLV

        LOG(DEBUG) << "Setting report details";
        channel_scan_result_tlv->radio_uid()       = ruid;
        channel_scan_result_tlv->operating_class() = operating_class;
        channel_scan_result_tlv->channel()         = channel;

        LOG(DEBUG) << "Setting report success status";
        channel_scan_result_tlv->success() = scan_status;
        if (channel_scan_result_tlv->success() !=
            wfa_map::tlvProfile2ChannelScanResult::eScanStatus::SUCCESS) {
            // If the status is not set to "success" then there is no need to set the other fields.
            return true;
        }

        LOG(DEBUG) << "Setting report timestamp";

        const auto &scan_start_timestamp = utils::get_ISO_8601_timestamp_string(scan_start_time);
        if (!channel_scan_result_tlv->set_timestamp(scan_start_timestamp.c_str(),
                                                    scan_start_timestamp.size())) {
            LOG(DEBUG) << "Failed to set timestamp in tlvProfile2ChannelScanResult!";
            return false;
        }

        // totalNoise will be used to calculate the average noise level for the channel.
        int totalNoise       = 0;
        int totalUtilization = 0;
        int neighbor_idx     = 0;
        for (const auto &neighbor : neighbors) {
            LOG(DEBUG) << "Filling neighbor structure #" << (neighbor_idx + 1);
            auto neighbor_res = channel_scan_result_tlv->create_neighbors_list();
            if (!neighbor_res) {
                LOG(ERROR) << "Failed to create neighbor list";
                return false;
            }
            if (!fill_scan_result_tlv_with_neighbors(neighbor, neighbor_res)) {
                LOG(ERROR) << "Failed to fill neighbor structure #" << (neighbor_idx + 1);
                return false;
            }
            if (!channel_scan_result_tlv->add_neighbors_list(neighbor_res)) {
                LOG(ERROR) << "Failed to add neighbor #" << (neighbor_idx + 1) << " to TLV";
                return false;
            }
            // Used to set TLV noise & utilization field later on
            totalNoise += neighbor.noise_dBm;
            totalUtilization += neighbor.channel_utilization;
            neighbor_idx++;
        }
        if (channel_scan_result_tlv->neighbors_list_length() != 0) {
            channel_scan_result_tlv->noise() =
                totalNoise / channel_scan_result_tlv->neighbors_list_length();
            channel_scan_result_tlv->utilization() =
                totalUtilization / channel_scan_result_tlv->neighbors_list_length();
        } else {
            LOG(DEBUG) << "No neighbors were found, setting noise and utilization to 0.";
            channel_scan_result_tlv->noise()       = 0;
            channel_scan_result_tlv->utilization() = 0;
        }
        /**
         * If the channel is a DFS channel, the scan will be passive
         *      only listen, without sending probes.
         * If the channel is a non-DFS channel, the scan will be active
         *      sending probes
         * 
         * Need to see if there is a way to report from the Driver if the result was returned from
         * an active/passive scan and not whather the channel is DFS or not
         * Need to be resolved as part of PPM-1045.
         */
        channel_scan_result_tlv->scan_type() =
            son::wireless_utils::is_dfs_channel(channel)
                ? wfa_map::tlvProfile2ChannelScanResult::eScanType::SCAN_WAS_PASSIVE_SCAN
                : wfa_map::tlvProfile2ChannelScanResult::eScanType::SCAN_WAS_ACTIVE_SCAN;
        return true;
    };

    const auto timestamp = utils::get_ISO_8601_timestamp_string();
    if (timestamp.empty()) {
        LOG(ERROR) << "Failed to create timestamp string";
        return false;
    }

    const auto request_info =
        std::static_pointer_cast<sControllerRequestInfo>(request->request_info);
    const auto mid                  = request_info->mid;
    const auto src_mac              = request_info->src_mac;
    const auto preform_fresh_scan   = request_info->perform_fresh_scan;
    const auto scan_start_timestamp = request->scan_start_timestamp;

    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SCAN_REPORT_MESSAGE)) {
        LOG(ERROR) << "Failed to create CMDU of type CHANNEL_SCAN_REPORT_MESSAGE";
        return false;
    }

    if (!add_report_timestamp_tlv(timestamp)) {
        LOG(ERROR) << "Failed to add Timestamp TLV to CHANNEL_SCAN_REPORT_MESSAGE";
        return false;
    }

    auto db = AgentDB::get();

    int result_tlv_count = 0;
    for (auto &radio_scan_iter : request->radio_scans) {
        // Get Scan info
        const auto radio_iface = radio_scan_iter.first;
        const auto radio_scan  = radio_scan_iter.second;
        const auto scan_status = radio_scan->scan_status;

        // Load stored scanned neighbors map
        auto radio = db->radio(radio_iface);
        if (!radio) {
            LOG(ERROR) << "No radio with iface '" << radio_iface << "' found!";
            return false;
        }
        const auto &stored_scanned_neighbors_map = radio->channel_scan_results;

        if (preform_fresh_scan == wfa_map::tlvProfile2ChannelScanRequest::ePerformFreshScan::
                                      PERFORM_A_FRESH_SCAN_AND_RETURN_RESULTS) {
            /**
             * A fresh scan was requested
             * Iterate over operating classed
             */
            for (auto &op_cls_iter : radio_scan->operating_classes) {
                const auto operating_class     = op_cls_iter.operating_class;
                const auto channel_list_length = op_cls_iter.channel_list_length;
                const auto channel_list        = op_cls_iter.channel_list;
                for (int chan_idx = 0; chan_idx < channel_list_length; chan_idx++) {
                    const auto channel = channel_list[chan_idx];
                    /**
                     * Check if channel has any stored results
                     * It is possible that a channel has no neighbors
                     */
                    if (stored_scanned_neighbors_map.find(channel) ==
                        stored_scanned_neighbors_map.end()) {
                        LOG(TRACE) << "There are no stored results for channel #" << channel;
                        continue;
                    }
                    /**
                     * Check if stored results are from the current request
                     * Old results are disregarded.
                     */
                    if (stored_scanned_neighbors_map.at(channel).first !=
                        request->scan_start_timestamp) {
                        LOG(TRACE) << "The results stored for channel #" << channel
                                   << " are not part of the current scan.";
                        continue;
                    }

                    LOG(TRACE) << "Adding new Scan-Result TLV for ["
                               << "radio: " << radio_iface << ", "
                               << "operating-class: " << operating_class << ", "
                               << "channel: " << channel << "]";
                    if (!add_scan_result_tlv(radio->front.iface_mac, operating_class, channel,
                                             scan_status, scan_start_timestamp,
                                             stored_scanned_neighbors_map.at(channel).second)) {
                        LOG(ERROR)
                            << "Failed to add Scan-Result TLV to CHANNEL_SCAN_REPORT_MESSAGE";
                        return false;
                    }
                    LOG(DEBUG) << "Added Scan-Result TLV #" << result_tlv_count++ << " ["
                               << "radio: " << radio_iface << ", "
                               << "operating-class: " << operating_class << ", "
                               << "channel: " << channel << "] to CHANNEL_SCAN_REPORT_MESSAGE";
                }
            }

        } else {
            /**
             * RETURN_STORED_RESULTS_OF_LAST_SUCCESSFUL_SCAN
             * The given scan request requested to returned all stored results
             * Iterate over the stored scanned neighbors lists
             */
            for (const auto &stored_scanned_neighbor_item : stored_scanned_neighbors_map) {
                /**
                 *  The scanned neighbors lists are stored in a map of
                 *      Key: channel number
                 *      Value: result pair
                 *          First: Timestamp of associated request
                 *          Second: vector of Stored Neighbors
                 */
                const auto channel = stored_scanned_neighbor_item.first;

                // Get operating class of channel according to current radio's bandwidth.
                beerocks::message::sWifiChannel wifi_channel;
                wifi_channel.channel           = channel;
                wifi_channel.channel_bandwidth = radio->bandwidth;
                const auto operating_class =
                    son::wireless_utils::get_operating_class_by_channel(wifi_channel);

                LOG(TRACE) << "Creating Scan-Result TLV for ["
                           << "radio: " << radio_iface << ", "
                           << "operating-class: " << operating_class << ", "
                           << "channel: " << channel << "]";
                if (!add_scan_result_tlv(radio->front.iface_mac, operating_class, channel,
                                         scan_status, stored_scanned_neighbor_item.second.first,
                                         stored_scanned_neighbor_item.second.second)) {
                    LOG(ERROR) << "Failed to add Scan-Result TLV to CHANNEL_SCAN_REPORT_MESSAGE";
                    return false;
                }
                LOG(DEBUG) << "Added Scan-Result TLV #" << result_tlv_count++ << " ["
                           << "radio: " << radio_iface << ", "
                           << "operating-class: " << operating_class << ", "
                           << "channel: " << channel << "] to CHANNEL_SCAN_REPORT_MESSAGE";
            }
        }
    }

    LOG(TRACE) << "Sending CHANNEL_SCAN_REPORT_MESSAGE to the originator, mid=" << std::hex << mid;
    LOG(DEBUG) << "CHANNEL_SCAN_REPORT_MESSAGE contains " << result_tlv_count
               << " Scan-Result TLV(s)";
    return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, db->bridge.mac);
}
