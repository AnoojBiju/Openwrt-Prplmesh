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

void ChannelScanTask::work() {}

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
    return false;
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
    return false;
}

bool ChannelScanTask::send_channel_scan_report_to_controller(
    const std::shared_ptr<sScanRequest> request)
{
    return false;
}
