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
    return false;
}

bool ChannelScanTask::handle_channel_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac)
{
    return false;
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
