/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "cac_status_database.h"
#include "cac_capabilities_database.h"

namespace beerocks {

CacAvailableChannels CacStatusDatabase::get_available_channels(const sMacAddr &radio_mac) const
{
    auto it = m_available_channels.find(radio_mac);
    if (it == m_available_channels.end()) {
        return CacAvailableChannels();
    }
    return it->second;
}

CacNonOccupancyChannels
CacStatusDatabase::get_non_occupancy_channels(const sMacAddr &radio_mac) const
{
    auto it = m_non_occupancy_channels.find(radio_mac);
    if (it == m_non_occupancy_channels.end()) {
        return CacAvailableChannels();
    }
    return it->second;
}

CacActiveChannels CacStatusDatabase::get_active_channels(const sMacAddr &radio_mac) const
{
    auto it = m_active_channels.find(radio_mac);
    if (it == m_active_channels.end()) {
        return CacAvailableChannels();
    }
    return it->second;
}

bool CacStatusDatabase::update_cac_status_db(const AgentDB::sRadio *radio)
{
    if (!radio) {
        return false;
    }

    CacAvailableChannels available_channels;
    CacNonOccupancyChannels non_occupancy_channels;
    CacActiveChannels active_channels;

    for (const auto &channel_channel_info : radio->channels_list) {
        uint8_t channel    = channel_channel_info.first;
        auto &channel_info = channel_channel_info.second;
        sCacStatus cac_status;

        switch (channel_info.dfs_state) {
        case beerocks_message::eDfsState::AVAILABLE:
            for (auto &bw_info : channel_info.supported_bw_list) {
                beerocks::message::sWifiChannel wifi_ch(channel, bw_info.bandwidth);
                cac_status.operating_class =
                    son::wireless_utils::get_operating_class_by_channel(wifi_ch);
                if (!cac_status.operating_class) {
                    LOG(WARNING) << "Skipping invalid operating class for channel: " << channel;
                    continue;
                }
                cac_status.channel = channel;

                // TODO: calculate duration value (PPM-2276)
                cac_status.duration = std::chrono::seconds(0);
                available_channels.push_back(cac_status);
            }
            break;
        case beerocks_message::eDfsState::UNAVAILABLE:
            for (auto &bw_info : channel_info.supported_bw_list) {
                beerocks::message::sWifiChannel wifi_ch(channel, bw_info.bandwidth);
                cac_status.operating_class =
                    son::wireless_utils::get_operating_class_by_channel(wifi_ch);
                if (!cac_status.operating_class) {
                    LOG(WARNING) << "Skipping invalid operating class for channel: " << channel;
                    continue;
                }
                cac_status.channel = channel;

                // TODO: calculate duration value (PPM-2275)
                cac_status.duration = std::chrono::seconds(0);
                non_occupancy_channels.push_back(cac_status);
            }
            break;
        case beerocks_message::eDfsState::USABLE:
            for (auto &bw_info : channel_info.supported_bw_list) {
                beerocks::message::sWifiChannel wifi_ch(channel, bw_info.bandwidth);
                cac_status.operating_class =
                    son::wireless_utils::get_operating_class_by_channel(wifi_ch);
                if (!cac_status.operating_class) {
                    LOG(WARNING) << "Skipping invalid operating class for channel: " << channel;
                    continue;
                }
                cac_status.channel = channel;
                if (std::chrono::steady_clock::now() > radio->cac_completion_time) {
                    LOG(WARNING) << "Exceeded estimated CAC completion time for radio "
                                 << radio->front.iface_mac;
                    continue;
                }
                cac_status.duration = std::chrono::duration_cast<std::chrono::seconds>(
                    radio->cac_completion_time - std::chrono::steady_clock::now());
                active_channels.push_back(cac_status);
            }
            break;
        case beerocks_message::eDfsState::NOT_DFS:
            continue;
        default:
            LOG(ERROR) << "Undefined DFS state " << channel_info.dfs_state
                       << ", radio: " << radio->front.iface_mac;
            continue;
        }
    }

    if (available_channels.empty() && non_occupancy_channels.empty() && active_channels.empty()) {
        LOG(DEBUG) << "No CAC data to update for radio " << radio->front.iface_mac;
        return false;
    }

    if (!available_channels.empty()) {
        std::sort(available_channels.begin(), available_channels.end());
        m_available_channels.emplace(radio->front.iface_mac, available_channels);
    }

    if (!non_occupancy_channels.empty()) {
        std::sort(non_occupancy_channels.begin(), non_occupancy_channels.end());
        m_non_occupancy_channels.emplace(radio->front.iface_mac, non_occupancy_channels);
    }

    if (!active_channels.empty()) {
        std::sort(active_channels.begin(), active_channels.end());
        m_active_channels.emplace(radio->front.iface_mac, active_channels);
    }

    return true;
}

bool CacStatusDatabase::add_cac_status_report_tlv(
    const AgentDB::sRadio *radio,
    const std::shared_ptr<wfa_map::tlvProfile2CacStatusReport> cac_status_report_tlv)
{
    if (!radio) {
        return false;
    }

    if (!update_cac_status_db(radio)) {
        return false;
    }

    auto available_channels = get_available_channels(radio->front.iface_mac);
    if (!available_channels.empty() &&
        !cac_status_report_tlv->alloc_available_channels(available_channels.size())) {
        LOG(ERROR) << "Failed to allocate " << available_channels.size()
                   << " structures for available channels";
    }

    for (unsigned int i = 0; i < available_channels.size(); ++i) {
        auto &available_ref           = std::get<1>(cac_status_report_tlv->available_channels(i));
        available_ref.operating_class = available_channels[i].operating_class;
        available_ref.channel         = available_channels[i].channel;
        if (son::wireless_utils::is_dfs_channel(available_channels[i].channel)) {
            available_ref.minutes_since_cac_completion = static_cast<uint16_t>(
                std::chrono::duration_cast<std::chrono::minutes>(available_channels[i].duration)
                    .count());
        } else {
            // Set to zero for non-DFS channels
            available_ref.minutes_since_cac_completion = 0;
        }
    }

    auto non_occupancy_channels = get_non_occupancy_channels(radio->front.iface_mac);
    if (!non_occupancy_channels.empty() &&
        !cac_status_report_tlv->alloc_detected_pairs(non_occupancy_channels.size())) {
        LOG(ERROR) << "Failed to allocate " << non_occupancy_channels.size()
                   << " structures for non-occupancy channels";
    }

    for (unsigned int i = 0; i < non_occupancy_channels.size(); ++i) {
        auto &detected_ref = std::get<1>(cac_status_report_tlv->detected_pairs(i));
        detected_ref.operating_class_detected = non_occupancy_channels[i].operating_class;
        detected_ref.channel_detected         = non_occupancy_channels[i].channel;
        detected_ref.duration = static_cast<uint16_t>(non_occupancy_channels[i].duration.count());
    }

    auto active_channels = get_active_channels(radio->front.iface_mac);
    if (!active_channels.empty() &&
        !cac_status_report_tlv->alloc_active_cac_pairs(active_channels.size())) {
        LOG(ERROR) << "Failed to allocate " << active_channels.size()
                   << " structures for active channels";
    }

    for (unsigned int i = 0; i < active_channels.size(); ++i) {
        auto &active_ref = std::get<1>(cac_status_report_tlv->active_cac_pairs(i));
        active_ref.operating_class_active_cac = active_channels[i].operating_class;
        active_ref.channel_active_cac         = active_channels[i].channel;
        uint32_t duration = static_cast<uint32_t>(active_channels[i].duration.count());
        memcpy(active_ref.countdown, &duration, 3);
    }

    return true;
}

sCacCompletionStatus CacStatusDatabase::get_completion_status(const AgentDB::sRadio *radio) const
{
    sCacCompletionStatus ret;

    if (!radio) {
        return ret;
    }

    // TODO: Below condition should not be reached (PPM-1833).
    if (!radio->last_switch_channel_request) {
        LOG(WARNING) << "No switch channel request to relate to, thus completion status is empty"
                     << " for radio " << radio->front.iface_mac;
        return ret;
    }
    uint8_t main_channel = radio->last_switch_channel_request->channel;

    auto channel_info = radio->channels_list.find(main_channel);
    if (channel_info == radio->channels_list.end()) {
        LOG(ERROR) << "Can't find channel info for " << main_channel
                   << " thus completion status is empty";
        return ret;
    }

    // main operating class and channel
    message::sWifiChannel wifi_ch(main_channel, radio->last_switch_channel_request->bandwidth);
    ret.channel         = main_channel;
    ret.operating_class = son::wireless_utils::get_operating_class_by_channel(wifi_ch);

    // fill the detected operating class and channels.
    if (channel_info->second.dfs_state == beerocks_message::eDfsState::UNAVAILABLE) {
        ret.completion_status     = sCacCompletionStatus::eCacCompletionStatus::RADAR_DETECTED;
        auto overlapping_channels = son::wireless_utils::get_overlapping_channels(
            radio->last_switch_channel_request->channel);
        // TODO: Add missing values. See PPM-1089.
        for (auto &overlap_ch : overlapping_channels) {
            message::sWifiChannel overlap_wifi_ch(overlap_ch.first, overlap_ch.second);
            ret.overlapping_channels.emplace_back(
                son::wireless_utils::get_operating_class_by_channel(overlap_wifi_ch),
                overlap_ch.first);
        }
    } else {
        ret.completion_status = sCacCompletionStatus::eCacCompletionStatus::SUCCESSFUL;
    }

    return ret;
}

bool CacStatusDatabase::add_cac_completion_report_tlv(
    const AgentDB::sRadio *radio,
    const std::shared_ptr<wfa_map::tlvProfile2CacCompletionReport> cac_completion_report_tlv)
{
    if (!radio) {
        return false;
    }

    const auto &cac_radio = cac_completion_report_tlv->create_cac_radios();
    if (!cac_radio) {
        LOG(ERROR) << "Failed to create cac radio for " << radio->front.iface_mac;
        return false;
    }

    cac_radio->radio_uid()             = radio->front.iface_mac;
    const auto &cac_completion         = get_completion_status(radio);
    cac_radio->operating_class()       = cac_completion.operating_class;
    cac_radio->channel()               = cac_completion.channel;
    cac_radio->cac_completion_status() = cac_completion.completion_status;

    if (!cac_completion.overlapping_channels.empty()) {
        cac_radio->alloc_detected_pairs(cac_completion.overlapping_channels.size());
        for (unsigned int i = 0; i < cac_completion.overlapping_channels.size(); ++i) {
            if (std::get<0>(cac_radio->detected_pairs(i))) {
                auto &cac_detected_pair = std::get<1>(cac_radio->detected_pairs(i));
                cac_detected_pair.operating_class_detected =
                    cac_completion.overlapping_channels[i].first;
                cac_detected_pair.channel_detected = cac_completion.overlapping_channels[i].second;
            }
        }
    }
    cac_completion_report_tlv->add_cac_radios(cac_radio);
    return true;
}

} // namespace beerocks
