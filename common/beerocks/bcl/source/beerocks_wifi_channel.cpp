/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_utils.h>
#include <bcl/beerocks_wifi_channel.h>
#include <bcl/son/son_wireless_utils.h>
namespace beerocks {

WifiChannel::WifiChannel() { initialize_empty_wifi_channel_members(); }

WifiChannel::WifiChannel(uint8_t channel, uint16_t center_frequency, eWiFiBandwidth bandwidth,
                         bool ext_above_secondary)
{
    beerocks::eFreqType freq_type = son::wireless_utils::which_freq_type(center_frequency);

    if (!are_params_valid(channel, freq_type, center_frequency, bandwidth)) {
        LOG(ERROR) << "invalid wifiChannel params. Creating an empty channel instead";
        initialize_empty_wifi_channel_members();
    } else if (freq_type == eFreqType::FREQ_6G && bandwidth == eWiFiBandwidth::BANDWIDTH_160) {
        /*
        according to the P802.11ax_D7.0 standard, Section 9.4.2.249:
        center_frequency_1 shall be the center frequency of the primary 80MHz channel,
        and center_frequency_2 shall be the center frequency of the 160MHz channel
        */
        auto channel_it = son::wireless_utils::channels_table_6g.find(channel);
        auto primary_80mhz_center_channel_it =
            channel_it->second.find(eWiFiBandwidth::BANDWIDTH_80);
        auto primary_80mhz_center_frequency = son::wireless_utils::channel_to_freq(
            primary_80mhz_center_channel_it->second.center_channel, eFreqType::FREQ_6G);

        initialize_wifi_channel_members(channel, freq_type, primary_80mhz_center_frequency,
                                        center_frequency, bandwidth, ext_above_secondary);
    } else {
        initialize_wifi_channel_members(channel, freq_type, center_frequency, 0, bandwidth,
                                        ext_above_secondary);
    }
}

WifiChannel::WifiChannel(uint8_t channel, eFreqType freq_type, eWiFiBandwidth bandwidth,
                         bool ext_above_secondary)
{
    uint16_t center_frequency = son::wireless_utils::channel_to_vht_center_freq(
        channel, freq_type, bandwidth, ext_above_secondary);

    if (!are_params_valid(channel, freq_type, center_frequency, bandwidth)) {
        LOG(ERROR) << "invalid wifiChannel params. Creating an empty channel instead";
        initialize_empty_wifi_channel_members();
    } else if (m_freq_type == eFreqType::FREQ_6G && bandwidth == eWiFiBandwidth::BANDWIDTH_160) {
        /*
        according to the P802.11ax_D7.0 standard, Section 9.4.2.249:
        center_frequency_1 shall be the center frequency of the primary 80MHz channel,
        and center_frequency_2 shall be the center frequency of the 160MHz channel
        */
        auto channel_it = son::wireless_utils::channels_table_6g.find(channel);
        auto primary_80mhz_center_channel_it =
            channel_it->second.find(eWiFiBandwidth::BANDWIDTH_80);
        auto primary_80mhz_center_frequency = son::wireless_utils::channel_to_freq(
            primary_80mhz_center_channel_it->second.center_channel, eFreqType::FREQ_6G);

        initialize_wifi_channel_members(channel, freq_type, primary_80mhz_center_frequency,
                                        center_frequency, bandwidth, ext_above_secondary);
    } else {
        initialize_wifi_channel_members(channel, freq_type, center_frequency, 0, bandwidth,
                                        ext_above_secondary);
    }
}

WifiChannel::WifiChannel(const WifiChannel &wc) { *this = wc; }

WifiChannel &WifiChannel::operator=(const WifiChannel &wc)
{
    m_channel             = wc.m_channel;
    m_freq_type           = wc.m_freq_type;
    m_center_frequency    = wc.m_center_frequency;
    m_center_frequency_2  = wc.m_center_frequency_2;
    m_bandwidth           = wc.m_bandwidth;
    m_ext_above_primary   = wc.m_ext_above_primary;
    m_ext_above_secondary = wc.m_ext_above_secondary;
    m_is_dfs              = wc.m_is_dfs;
    m_tx_power            = wc.m_tx_power;
    m_radar_affected      = wc.m_radar_affected;
    return *this;
}

uint8_t WifiChannel::get_channel() const { return m_channel; }

void WifiChannel::set_channel(uint8_t channel)
{
    switch (m_freq_type) {
    case eFreqType::FREQ_24G: {
        if (son::wireless_utils::channels_table_24g.find(channel) ==
            son::wireless_utils::channels_table_24g.end()) {
            LOG(ERROR) << "Failed set a channel " << channel << " in 2.4ghz band type";
            return;
        }
    } break;
    case eFreqType::FREQ_5G: {
        if (son::wireless_utils::channels_table_5g.find(channel) ==
            son::wireless_utils::channels_table_5g.end()) {
            LOG(ERROR) << "Failed set a channel " << channel << " in 5ghz band type";
            return;
        }
    } break;
    case eFreqType::FREQ_6G: {
        if (son::wireless_utils::channels_table_6g.find(channel) ==
            son::wireless_utils::channels_table_6g.end()) {
            LOG(ERROR) << "Failed set a channel " << channel << " in 6ghz band type";
            return;
        }
    } break;
    default: {
        LOG(INFO)
            << "Failed set channel to an empty wifiChannel, because the bandwidth is unknown. "
               "use assignment operator instead";
        return;
    } break;
    }
    m_channel = channel;

    if (m_freq_type == FREQ_6G && m_bandwidth == BANDWIDTH_160) {
        m_center_frequency = son::wireless_utils::channel_to_vht_center_freq(
            m_channel, m_freq_type, BANDWIDTH_80, m_ext_above_secondary);
        m_center_frequency_2 = son::wireless_utils::channel_to_vht_center_freq(
            m_channel, m_freq_type, BANDWIDTH_160, m_ext_above_secondary);
    } else {
        m_center_frequency = son::wireless_utils::channel_to_vht_center_freq(
            m_channel, m_freq_type, m_bandwidth, m_ext_above_secondary);
        m_center_frequency_2 = 0;
    }
}

uint16_t WifiChannel::get_center_frequency() const { return m_center_frequency; }

uint16_t WifiChannel::get_center_frequency_2() const { return m_center_frequency_2; }

eWiFiBandwidth WifiChannel::get_bandwidth() const { return m_bandwidth; }

void WifiChannel::set_bandwidth(eWiFiBandwidth bw)
{
    if (bw == eWiFiBandwidth::BANDWIDTH_UNKNOWN) {
        LOG(ERROR) << "Failed to set bandwidth. Invalid input: unknown bandwidth";
    } else {
        auto new_center_frequency = son::wireless_utils::channel_to_vht_center_freq(
            m_channel, m_freq_type, bw, m_ext_above_secondary);
        if (new_center_frequency < m_center_frequency) {
            m_ext_above_primary   = -1;
            m_ext_above_secondary = false;
        } else if (new_center_frequency > m_center_frequency) {
            m_ext_above_primary   = 1;
            m_ext_above_secondary = true;
        } else {
            m_ext_above_primary   = 0;
            m_ext_above_secondary = false;
        }
        m_center_frequency = new_center_frequency;
        m_bandwidth        = bw;
    }
}

eFreqType WifiChannel::get_freq_type() const { return m_freq_type; }

int WifiChannel::get_ext_above_primary() const { return m_ext_above_primary; }

bool WifiChannel::get_ext_above_secondary() const { return m_ext_above_secondary; }

bool WifiChannel::is_empty() const { return m_freq_type == beerocks::FREQ_UNKNOWN; }

bool WifiChannel::is_dfs_channel() const
{
    return (m_freq_type == eFreqType::FREQ_5G) && son::wireless_utils::is_dfs_channel(m_channel);
}

uint8_t WifiChannel::get_tx_power() const { return m_tx_power; }

void WifiChannel::set_tx_power(uint8_t tx_power) { m_tx_power = tx_power; }

uint8_t WifiChannel::get_radar_affected() const { return m_radar_affected; }

void WifiChannel::set_radar_affected(uint8_t radar_affected) { m_radar_affected = radar_affected; }

std::ostream &operator<<(std::ostream &out, const WifiChannel &wifi_channel)
{
    if (wifi_channel.is_empty()) {
        return (out << "Empty WifiChannel");
    }
    std::string center_freq_2_str =
        ((wifi_channel.m_freq_type == eFreqType::FREQ_6G) &&
         (wifi_channel.m_bandwidth == eWiFiBandwidth::BANDWIDTH_160))
            ? ", Center Frequency 2: " + wifi_channel.m_center_frequency_2
            : "";

    std::string is_dfs_str = "";
    if (wifi_channel.m_freq_type == eFreqType::FREQ_5G) {
        is_dfs_str = ", Is DFS Channel: ";
        if (wifi_channel.m_is_dfs) {
            is_dfs_str += "Yes";
        } else {
            is_dfs_str += "No";
        }
    }

    return (out << "*WifiChannel* Channel Number: " << int(wifi_channel.m_channel)
                << ", Bandwidth: "
                << beerocks::utils::convert_bandwidth_to_int(wifi_channel.m_bandwidth)
                << "Mhz, Center Frequency: " << wifi_channel.m_center_frequency << center_freq_2_str
                << ", Frequency Type: "
                << beerocks::utils::convert_frequency_type_to_string(wifi_channel.m_freq_type)
                << is_dfs_str << ", ext_above_primary: " << wifi_channel.m_ext_above_primary
                << ", ext_above_secondary: " << wifi_channel.m_ext_above_secondary);
}

void WifiChannel::initialize_empty_wifi_channel_members()
{
    m_channel             = 0;
    m_center_frequency    = 0;
    m_center_frequency_2  = 0;
    m_bandwidth           = eWiFiBandwidth::BANDWIDTH_UNKNOWN;
    m_ext_above_secondary = false;
    m_freq_type           = eFreqType::FREQ_UNKNOWN;
    m_ext_above_primary   = 0;
    m_is_dfs              = false;
    m_tx_power            = 0;
    m_radar_affected      = 0;
}

void WifiChannel::initialize_wifi_channel_members(uint8_t channel, eFreqType freq_type,
                                                  uint16_t center_frequency,
                                                  uint16_t center_frequency_2,
                                                  eWiFiBandwidth bandwidth,
                                                  bool ext_above_secondary)
{
    m_channel             = channel;
    m_freq_type           = freq_type;
    m_center_frequency    = center_frequency;
    m_center_frequency_2  = center_frequency_2;
    m_bandwidth           = bandwidth;
    m_ext_above_secondary = ext_above_secondary;
    m_tx_power            = 0;
    m_radar_affected      = 0;

    if (m_freq_type == eFreqType::FREQ_5G) {
        m_is_dfs = son::wireless_utils::is_dfs_channel(m_channel);
    } else {
        m_is_dfs = false;
    }
    unsigned int center_channel = son::wireless_utils::freq_to_channel(center_frequency);
    if (channel < center_channel) {
        m_ext_above_primary = 1;
    } else if (channel > center_channel) {
        m_ext_above_primary = -1;
    } else {
        m_ext_above_primary = 0;
    }
}

bool WifiChannel::are_params_valid(uint8_t channel, eFreqType freq_type, uint16_t center_frequency,
                                   eWiFiBandwidth bandwidth)
{
    if (bandwidth == eWiFiBandwidth::BANDWIDTH_UNKNOWN ||
        bandwidth == eWiFiBandwidth::BANDWIDTH_MAX) {
        LOG(ERROR) << "The bandwidth Failed be "
                   << beerocks::utils::convert_bandwidth_to_int(bandwidth);
        return false;
    }

    if (center_frequency < BAND_24G_MIN_FREQ) {
        LOG(ERROR) << "Center frequency (" << center_frequency << ") of channel " << channel
                   << " is below the minimum";
        return false;
    }

    if (center_frequency > BAND_6G_MAX_FREQ) {
        LOG(ERROR) << "Center frequency (" << center_frequency << ") of channel " << channel
                   << " is above the maximum";
        return false;
    }

    switch (freq_type) {
    case eFreqType::FREQ_24G: {
        if (son::wireless_utils::channels_table_24g.find(channel) ==
            son::wireless_utils::channels_table_24g.end()) {
            LOG(ERROR) << "Failed find " << channel << " channel in 2.4ghz channels table.";
            return false;
        }
    } break;
    case eFreqType::FREQ_5G: {
        auto channel_it = son::wireless_utils::channels_table_5g.find(channel);
        if (channel_it == son::wireless_utils::channels_table_5g.end()) {
            LOG(ERROR) << "Failed find " << channel << " channel in 5ghz channels table.";
            return false;
        } else if (channel_it->second.find(bandwidth) == channel_it->second.end()) {
            LOG(ERROR) << "Failed find bandwidth "
                       << beerocks::utils::convert_bandwidth_to_int(bandwidth) << "MHz of channel "
                       << channel << " in 5ghz channels table.";
            return false;
        }
    } break;
    case eFreqType::FREQ_6G: {
        auto channel_it = son::wireless_utils::channels_table_6g.find(channel);
        if (channel_it == son::wireless_utils::channels_table_6g.end()) {
            LOG(ERROR) << "Failed find " << channel << " channel in 6ghz channels table.";
            return false;
        } else if (channel_it->second.find(bandwidth) == channel_it->second.end()) {
            LOG(ERROR) << "Failed find bandwidth "
                       << beerocks::utils::convert_bandwidth_to_int(bandwidth) << "MHz of channel "
                       << channel << " in 6ghz channels table.";
            return false;
        }

        if (bandwidth == eWiFiBandwidth::BANDWIDTH_160) {
            /*
            According to the standard, center_frequency_1 shall be the center frequency
            of the primary 80MHz channel, and center_frequency_2 shall be the center frequency
            of the 160MHz channel
            */
            auto primary_80mhz_center_channel_it =
                channel_it->second.find(eWiFiBandwidth::BANDWIDTH_80);
            if (primary_80mhz_center_channel_it == channel_it->second.end()) {
                LOG(ERROR) << "Failed find channel's " << channel
                           << " primary center channel of bandwidth 80MHz from "
                              "channels_table_6g. ";
                return false;
            }
        }
    } break;
    default: {
        LOG(ERROR) << "invalid band type "
                   << beerocks::utils::convert_frequency_type_to_string(m_freq_type)
                   << ". channel=" << channel;
        return false;
    } break;
    }
    return true;
}

} // namespace beerocks
