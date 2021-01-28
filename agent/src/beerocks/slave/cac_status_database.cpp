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

CacAvailableChannels CacStatusDatabase::get_availiable_channels(const sMacAddr &radio_mac) const
{
    CacAvailableChannels ret;

    auto db = AgentDB::get();

    const auto radio = db->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to find the Radio with mac: " << radio_mac;
        return ret;
    }

    for (const std::pair<uint8_t, AgentDB::sRadio::sChannelInfo> &channel_channel_info :
         radio->channels_list) {
        uint8_t channel = channel_channel_info.first;

        auto &channel_info = channel_channel_info.second;
        if (channel_info.get_dfs_state() == beerocks_message::eDfsState::USABLE ||
            channel_info.get_dfs_state() == beerocks_message::eDfsState::AVAILABLE) {

            std::transform(channel_info.supported_bw_list.begin(),
                           channel_info.supported_bw_list.end(), std::back_inserter(ret),
                           [channel](const beerocks_message::sSupportedBandwidth &supported) {
                               sCacStatus ret;

                               // channel
                               ret.channel = channel;

                               // operating class
                               beerocks::message::sWifiChannel wifi;
                               wifi.channel = channel;
                               wifi.channel_bandwidth =
                                   beerocks::utils::convert_bandwidth_to_int(supported.bandwidth);
                               ret.operating_class =
                                   son::wireless_utils::get_operating_class_by_channel(wifi);

                               // duration
                               // Todo: compute according to capabilities and
                               // duration if ACTIVE_CAC is the dfs state
                               // https://jira.prplfoundation.org/browse/PPM-1088
                               ret.duration = std::chrono::seconds(0);

                               return ret;
                           });
        }
    }
    return ret;
}

CacNonOccupancyChannels CacStatusDatabase::get_non_occupancy_channels(const sMacAddr &radio) const
{
    return {};
}

CacActiveChannels CacStatusDatabase::get_active_channels(const sMacAddr &radio) const { return {}; }

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
    beerocks::message::sWifiChannel wifi;
    wifi.channel = main_channel;
    wifi.channel_bandwidth =
        beerocks::utils::convert_bandwidth_to_int(radio->last_swich_channel_request->bandwidth);
    ret.first.operating_class = son::wireless_utils::get_operating_class_by_channel(wifi);

    // fill the detected operting class and channels.
    if (channel_info->second.get_dfs_state() == beerocks_message::eDfsState::UNAVAILABLE) {

        auto overlapping = son::wireless_utils::get_overlapping_channels(
            radio->last_swich_channel_request->channel);
        std::vector<std::pair<uint8_t, uint8_t>> radar_detected_operating_class_channel_list;
        std::transform(overlapping.begin(), overlapping.end(),
                       std::back_inserter(radar_detected_operating_class_channel_list),
                       [](const std::pair<uint8_t, beerocks::eWiFiBandwidth> &overlapping) {
                           beerocks::message::sWifiChannel wifi;
                           wifi.channel = overlapping.first;
                           wifi.channel_bandwidth =
                               beerocks::utils::convert_bandwidth_to_int(overlapping.second);
                           return std::make_pair(
                               son::wireless_utils::get_operating_class_by_channel(wifi),
                               overlapping.first);
                       });
        ret.second = radar_detected_operating_class_channel_list;
    }

    return ret;
}

} // namespace beerocks
