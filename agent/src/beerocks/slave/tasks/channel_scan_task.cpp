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
    return false;
}

bool ChannelScanTask::trigger_next_radio_scan(const std::shared_ptr<sScanRequest> request)
{
    return false;
}

bool ChannelScanTask::trigger_radio_scan(const std::string &radio_iface,
                                         const std::shared_ptr<sRadioScan> radio_scan_info)
{
    return false;
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
