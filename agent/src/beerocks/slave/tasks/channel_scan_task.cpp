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

#define FSM_MOVE_STATE(radio_iface, new_state)                                                     \
    ({                                                                                             \
        LOG(TRACE) << "CHANNEL_SCAN " << radio_iface                                               \
                   << " FSM: " << m_states_string.at(m_state[radio_iface]) << " --> "              \
                   << m_states_string.at(new_state);                                               \
        m_state[radio_iface] = new_state;                                                          \
    })

ChannelScanTask::ChannelScanTask(BackhaulManager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SCAN), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ChannelScanTask::work()
{
    for (auto &state_kv : m_state) {
        const auto &radio_iface = state_kv.first;
        auto &state             = state_kv.second;
        switch (state) {
        case eState::UNCONFIGURED: {
            //waiting for start_scan() call to initialize m_state with radio list.
            break;
        }
        case eState::INIT: {
            FSM_MOVE_STATE(radio_iface, eState::IDLE);
            break;
        }
        case eState::IDLE: {
            break;
        }
        default:
            break;
        }
    }
}

void ChannelScanTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
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
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void ChannelScanTask::start_scan()
{
    auto db = AgentDB::get();
    for (const auto &radio : db->get_radios_list()) {
        if (!radio) {
            continue;
        }

        LOG(DEBUG) << "Start scan channel on radio_iface=" << radio->front.iface_name;
        FSM_MOVE_STATE(radio->front.iface_name, eState::INIT);
    }
    // Call work() to not waste time, and start channel scan.
    work();
}

bool ChannelScanTask::handle_channel_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    auto channel_scan_request_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2ChannelScanRequest>();
    if (!channel_scan_request_tlv) {
        LOG(ERROR) << "getClass wfa_map::tlvProfile2ChannelScanRequest failed";
        return false;
    }

    LOG(INFO) << "Received CHANNEL_SCAN_REQUEST_MESSAGE, src_mac=" << src_mac
              << ", mid=" << std::hex << mid;

    // Print message content to log - placeholder until full implementation
    const auto &perform_fresh_scan = channel_scan_request_tlv->perform_fresh_scan();
    LOG(DEBUG) << "perform_fresh_scan=" << perform_fresh_scan;

    const auto &radio_list_length = channel_scan_request_tlv->radio_list_length();
    for (int radio_i = 0; radio_i < radio_list_length; ++radio_i) {
        const auto &radio_list = channel_scan_request_tlv->radio_list(radio_i);
        const auto radio_uid   = std::get<1>(radio_list).radio_uid();
        LOG(DEBUG) << "radio_list[" << radio_i << "] radio_uid=" << radio_uid;
    }

    // Build and send ACK message CMDU to the originator.
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return false;
    }

    // Zero Error Code TLVs in this ACK message

    LOG(DEBUG) << "Sending ACK message to the originator, mid=" << std::hex << mid;
    auto db = AgentDB::get();
    if (!m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, db->bridge.mac)) {
        LOG(ERROR) << "Failed to send ACK_MESSAGE back to controller";
        return false;
    }

    // Send channel scan report back - placeholder until full implementation
    if (!send_channel_scan_report(cmdu_rx, src_mac)) {
        LOG(ERROR) << "Failed to send CHANNEL_SCAN_REPORT_MESSAGE back to controller";
    }

    return true;
}

std::string
get_timestamp_string(std::chrono::system_clock::time_point stamp = std::chrono::system_clock::now())
{
    // Accourding to Multi-AP Specification Version 2.0, section 17.2.41, page 91:
    // Timestamp should be in the format:
    // '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z|[\+\-]\d{2}:\d{2})'
    // This function will return a time-date string format as defined in ISO 8601.
    // For example: 2016-09-28T14:50:31.456449Z or 2016-09-28T14:50:31.456449+06:00

    auto seconds_since_epoch =
        std::chrono::duration_cast<std::chrono::seconds>(stamp.time_since_epoch());

    // Construct time_t using 'seconds_since_epoch' rather than 'stamp' since it is
    // implementation-defined whether the value is rounded or truncated.
    std::time_t stamp_t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::time_point(seconds_since_epoch));

    // std::strftime() can convert the "now" timestamp into a string,
    // but it only supports up to a resolution of a second.
    // generating the first part of the data-time string:
    char buff[40];
    if (!std::strftime(buff, 40, "%Y-%m-%dT%H:%M:%S.", std::localtime(&stamp_t))) {
        return "";
    }

    // The subtraction bellow is used to get the fractional value of the second into the string.
    // Note: the "Z" at the end means zolo time (UTC+0). This function assume locale to always be UTC.
    // Unless we have a way to know our local, in which case, "Z" might be replaced with
    // the time delta (+03:00 for Israel, as an example).
    return std::string(buff) +
           std::to_string((stamp.time_since_epoch() - seconds_since_epoch).count()) + "Z";
}

bool ChannelScanTask::send_channel_scan_report(ieee1905_1::CmduMessageRx &cmdu_rx,
                                               const sMacAddr &src_mac)
{
    const auto timestamp = get_timestamp_string();
    if (timestamp.empty()) {
        LOG(ERROR) << "Fail to create timestamp string";
        return false;
    }

    // build 1905.1 message CMDU
    auto mid = cmdu_rx.getMessageId();
    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SCAN_REPORT_MESSAGE)) {
        LOG(ERROR) << "Create CMDU of type CHANNEL_SCAN_REPORT_MESSAGE failed";
        return false;
    }

    // Lambda function that fills the TLV neighbor structure.
    auto fill_scan_report_neighbor = [](const beerocks_message::sChannelScanResults &neighbor,
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
        neighbor_res->bss_load_element_present() =
            wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_NOT_PRESENT;

        // Channel Utilization
        // Since BSS Load Element Present is set to "Not Present" no need to set  Channel Utilization.
        // neighbor_res->channel_utilization() = neighbor.channel_utilization;

        // Station Count
        // Since BSS Load Element Present is set to "Not Present" no need to set Station Count.
        // neighbor_res->station_count() = 0;

        LOG(TRACE) << "Done filling report structure";
        return true;
    };

    // Lambda function that creates the Timestamp TLV.
    auto add_timestamp_TLV = [this](const std::string &timestamp) -> bool {
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
    auto add_report_TLV =
        [this, &fill_scan_report_neighbor](
            const sMacAddr &ruid, const uint8_t &operating_class, const uint8_t &channel,
            wfa_map::tlvProfile2ChannelScanResult::eScanStatus scan_status,
            std::chrono::system_clock::time_point scan_start_time,
            wfa_map::tlvProfile2ChannelScanResult::eScanType scan_type,
            std::vector<beerocks_message::sChannelScanResults> neighbors) -> bool {
        LOG(DEBUG) << "Creating report TLV";
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

        const auto &scan_start_timestamp = get_timestamp_string(scan_start_time);
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
            if (!fill_scan_report_neighbor(neighbor, neighbor_res)) {
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
        channel_scan_result_tlv->scan_type() = scan_type;
        return true;
    };

    if (!add_timestamp_TLV(timestamp)) {
        LOG(ERROR) << "Failed to add Timestamp TLV to CHANNEL_SCAN_REPORT_MESSAGE";
        return false;
    }

    auto db = AgentDB::get();
    LOG(TRACE) << "scan requests size: " << scan_requests.size();
    for (auto &scan_request_iter : scan_requests) {
        auto &ruid = scan_request_iter.first;
        LOG(TRACE) << "Creating report for radio: " << ruid;
        auto &scan_request = scan_request_iter.second;
        LOG(TRACE) << "Get radio struct for radio: " << ruid;
        auto db_radio = db->get_radio_by_mac(ruid);
        if (!db_radio) {
            LOG(ERROR) << "No radio with ruid '" << ruid << "' found!";
            return false;
        }
        LOG(TRACE) << "Getting operating classes list length for radio: " << ruid;
        const auto &operating_class_length = scan_request.radio.operating_classes_list_length();
        LOG(TRACE) << "operating classes list length: " << operating_class_length;
        for (int op_idx = 0; op_idx < operating_class_length; ++op_idx) {
            const auto &op_list = scan_request.radio.operating_classes_list(op_idx);
            if (!std::get<0>(op_list)) {
                LOG(ERROR) << "Failed to get operating classes list[" << op_idx
                           << "] for radio: " << scan_request.radio.radio_uid();
                return false;
            }
            auto &operating_class_item = std::get<1>(op_list);
            auto operating_class       = operating_class_item.operating_class();
            auto channel_list_length   = operating_class_item.channel_list_length();
            auto channel_list          = operating_class_item.channel_list(0);
            LOG(TRACE) << "Operating class #" << operating_class
                       << ", Channel-list length: " << channel_list_length;
            for (int c_idx = 0; c_idx < channel_list_length; c_idx++) {
                auto channel = channel_list[c_idx];
                LOG(TRACE) << "Getting neighbors for channel[" << c_idx << "]: " << channel;
                auto &stored_scanned_neighbors = db_radio->channel_scan_results;
                if (stored_scanned_neighbors.find(channel) == stored_scanned_neighbors.end()) {
                    LOG(TRACE) << "There are no stored results for channel #" << channel;
                    continue;
                }
                auto &neighbors = stored_scanned_neighbors.at(channel);
                LOG(TRACE) << "Found " << neighbors.size() << " neighbors for channel #" << channel;
                if (!add_report_TLV(ruid, operating_class, channel, scan_request.scan_status,
                                    scan_request.scan_start_timestamp, scan_request.scan_type,
                                    neighbors)) {
                    LOG(ERROR) << "Failed to create Scan Report TLV to CHANNEL_SCAN_REPORT_MESSAGE";
                    return false;
                }
                LOG(TRACE) << "Done setting TLV for [radio: " << ruid
                           << ", operating class: " << operating_class << " channel: " << channel
                           << "].";
            }
        }
    }

    LOG(DEBUG) << "Sending CHANNEL_SCAN_REPORT_MESSAGE to the originator, mid=" << std::hex << mid;
    return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, db->bridge.mac);
}
