/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "cac_status_database.h"
#include "agent_db.h"
#include "cac_capabilities_database.h"
#include <bcl/beerocks_utils.h>

namespace beerocks {

std::vector<sMacAddr> CacStatusDatabase::get_cac_radios() const
{
    // the list of radios is coming form the capabilities
    return CacCapabilitiesDatabase().get_cac_radios();
}

CacAvailableChannels CacStatusDatabase::get_available_channels(const sMacAddr &radio_mac) const
{
    CacAvailableChannels ret;

    auto db = AgentDB::get();

    const auto radio = db->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to find the Radio with mac: " << radio_mac;
        return ret;
    }

    for (const auto &channel_channel_info : radio->channels_list) {
        uint8_t channel    = channel_channel_info.first;
        auto &channel_info = channel_channel_info.second;

        if (channel_info.dfs_state == beerocks_message::eDfsState::USABLE ||
            channel_info.dfs_state == beerocks_message::eDfsState::AVAILABLE) {

            for (auto &bw_info : channel_info.supported_bw_list) {
                beerocks::message::sWifiChannel wifi_ch(channel, bw_info.bandwidth);
                sCacStatus cac_status;
                cac_status.channel = channel;
                cac_status.operating_class =
                    son::wireless_utils::get_operating_class_by_channel(wifi_ch);

                // Todo: https://jira.prplfoundation.org/browse/PPM-1088
                cac_status.duration = std::chrono::seconds(0);
                ret.push_back(cac_status);
            }
        }
    }
    return ret;
}

CacCompletionStatus CacStatusDatabase::get_completion_status(const sMacAddr &radio_mac) const
{
    CacCompletionStatus ret;

    auto db = AgentDB::get();

    const auto radio = db->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to find the Radio with mac: " << radio_mac;
        return ret;
    }

    if (!radio->last_swich_channel_request) {
        LOG(ERROR) << "No switch channel request to relate to, thus completion status is empty"
                   << " for radio " << radio_mac;
        return ret;
    }
    uint8_t main_channel = radio->last_swich_channel_request->channel;

    auto channel_info = radio->channels_list.find(main_channel);
    if (channel_info == radio->channels_list.end()) {
        LOG(ERROR) << "Can't find channel info for " << main_channel
                   << " thus completion status is empty";
        return ret;
    }

    // main operating class and chanel
    message::sWifiChannel wifi_ch(main_channel, radio->last_swich_channel_request->bandwidth);
    ret.first.operating_class = son::wireless_utils::get_operating_class_by_channel(wifi_ch);

    // fill the detected operting class and channels.
    if (channel_info->second.dfs_state == beerocks_message::eDfsState::UNAVAILABLE) {
        auto overlapping_channels = son::wireless_utils::get_overlapping_channels(
            radio->last_swich_channel_request->channel);

        for (auto &overlap_ch : overlapping_channels) {
            message::sWifiChannel overlap_wifi_ch(overlap_ch.first, overlap_ch.second);
            ret.second.emplace_back(
                son::wireless_utils::get_operating_class_by_channel(overlap_wifi_ch),
                overlap_ch.first);
        }
    }

    return ret;
}

} // namespace beerocks
