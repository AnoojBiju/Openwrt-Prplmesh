/* SPDX-License-Identifier: BSD-2-Clause-Patent AND ISC
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 * SPDX-FileCopyrightText: 2007, 2008 Johannes Berg
 * SPDX-FileCopyrightText: 2007 Andy Lutomirski
 * SPDX-FileCopyrightText: 2007 Mike Kershaw
 * SPDX-FileCopyrightText: 2008-2009 Luis R. Rodriguez
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

/**
 * This file uses code copied from `iw` (http://git.sipsolutions.net/iw.git/)
 *
 * Copyright (c) 2007, 2008 Johannes Berg
 * Copyright (c) 2007    Andy Lutomirski
 * Copyright (c) 2007    Mike Kershaw
 * Copyright (c) 2008-2009   Luis R. Rodriguez
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include "nl80211_client_impl.h"

#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bwl/base_802_11_defs.h>
#include <tlvf/CmduMessageTx.h>
#include <tlvf/ieee_80211/sMacHeader.h>

#include <easylogging++.h>

#include <linux/if_ether.h>
#include <linux/nl80211.h>
#include <linux/version.h>
#include <net/if.h>
#include <netlink/genl/genl.h>

#include <math.h>
namespace bwl {

std::string nl80211_parse_ifname(struct nlattr *tb[])
{
    std::string ifname;

    if (tb[NL80211_ATTR_IFNAME]) {
        size_t length    = nla_len(tb[NL80211_ATTR_IFNAME]);
        const char *data = static_cast<const char *>(nla_data(tb[NL80211_ATTR_IFNAME]));

        LOG_IF(length == 0, FATAL) << "Interface name is empty";
        LOG_IF(data[length - 1] != '\0', FATAL) << "Interface name is not null-terminated";

        ifname.assign(data);
    }

    return ifname;
}

nl80211_client_impl::nl80211_client_impl(std::unique_ptr<nl80211_socket> socket)
    : m_socket(std::move(socket))
{
}

bool nl80211_client_impl::get_interfaces(std::vector<std::string> &interfaces)
{
    interfaces.clear();

    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_INTERFACE, NLM_F_DUMP, [](struct nl_msg *msg) -> bool { return true; },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            std::string ifname = nl80211_parse_ifname(tb);
            if (!ifname.empty()) {
                interfaces.push_back(ifname);
            }
        });
}

bool nl80211_client_impl::get_interface_info(const std::string &interface_name,
                                             interface_info &interface_info)
{
    interface_info = {};

    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_INTERFACE, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);

            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            interface_info.name = nl80211_parse_ifname(tb);

            if (tb[NL80211_ATTR_IFINDEX]) {
                interface_info.index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
            } else {
                LOG(DEBUG) << "NL80211_ATTR_IFINDEX attribute is missing";
            }

            if (tb[NL80211_ATTR_MAC]) {
                const uint8_t *data = static_cast<const uint8_t *>(nla_data(tb[NL80211_ATTR_MAC]));

                tlvf::mac_from_array(data, interface_info.addr);
            }

            if (tb[NL80211_ATTR_SSID]) {
                size_t length       = nla_len(tb[NL80211_ATTR_SSID]);
                const uint8_t *data = static_cast<const uint8_t *>(nla_data(tb[NL80211_ATTR_SSID]));

                for (size_t i = 0; i < length; i++) {
                    interface_info.ssid += static_cast<char>(data[i]);
                }
            }

            if (tb[NL80211_ATTR_IFTYPE]) {
                interface_info.type = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
            } else {
                LOG(DEBUG) << "NL80211_ATTR_IFTYPE attribute is missing";
            }

            if (tb[NL80211_ATTR_WIPHY]) {
                interface_info.wiphy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
            } else {
                LOG(DEBUG) << "NL80211_ATTR_WIPHY attribute is missing";
            }

            if (tb[NL80211_ATTR_WIPHY_FREQ]) {
                interface_info.frequency = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
                interface_info.channel =
                    son::wireless_utils::freq_to_channel(interface_info.frequency);
                if (tb[NL80211_ATTR_CHANNEL_WIDTH]) {

                    // NL80211_ATTR_CENTER_FREQ1 attribute must be provided for bw 40 80 160
                    // NL80211_ATTR_CENTER_FREQ2 attribute must be provided for bw 80P80
                    switch (nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH])) {
                    case NL80211_CHAN_WIDTH_20_NOHT:
                    case NL80211_CHAN_WIDTH_20:
                        interface_info.bandwidth = 20;
                        break;
                    case NL80211_CHAN_WIDTH_40:
                        interface_info.bandwidth = 40;
                        break;
                    case NL80211_CHAN_WIDTH_80:
                        interface_info.bandwidth = 80;
                        break;
                    case NL80211_CHAN_WIDTH_80P80:
                        if (tb[NL80211_ATTR_CENTER_FREQ2]) {
                            interface_info.frequency_center2 =
                                nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);
                        }
                        interface_info.bandwidth = 160;
                        break;
                    case NL80211_CHAN_WIDTH_160:
                        interface_info.bandwidth = 160;
                        break;
                    default:
                        //unsupported values: ofdm bw 5 and 10
                        interface_info.bandwidth = 0;
                        break;
                    }
                    if (interface_info.bandwidth > 20 && tb[NL80211_ATTR_CENTER_FREQ1]) {
                        interface_info.frequency_center1 =
                            nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);
                    }
                }
            }
        });
}

bool nl80211_client_impl::get_radio_info(const std::string &interface_name, radio_info &radio_info)
{
    int last_band    = -1;
    bool width_40    = false;
    bool width_80    = false;
    bool width_80_80 = false;
    bool width_160   = false;

    radio_info = {};

    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_WIPHY, NLM_F_DUMP,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);

            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            if (!tb[NL80211_ATTR_WIPHY_BANDS]) {
                return;
            }

            struct nlattr *nl_band;
            int rem_band;

            const struct nlattr *nla = tb[NL80211_ATTR_WIPHY_BANDS];
            nla_for_each_attr(nl_band, static_cast<struct nlattr *>(nla_data(nla)), nla_len(nla),
                              rem_band)
            {
                struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 19, 1)
                int rem_iftype;
                struct nlattr *tb_iftype[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
#endif

                if (last_band != nl_band->nla_type) {
                    width_40    = false;
                    width_80    = false;
                    width_80_80 = false;
                    width_160   = false;
                    last_band   = nl_band->nla_type;

                    band_info band{};
                    radio_info.bands.push_back(band);
                }

                if (radio_info.bands.empty()) {
                    LOG(ERROR) << "Array of bands is empty";
                    return;
                }

                band_info &band = radio_info.bands.at(radio_info.bands.size() - 1);

                if (nla_parse(tb_band, NL80211_BAND_ATTR_MAX,
                              static_cast<nlattr *>(nla_data(nl_band)), nla_len(nl_band), NULL)) {
                    LOG(ERROR) << "Failed to parse wiphy band " << nl_band->nla_type + 1 << "!";
                    return;
                }

                if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
                    band.ht_supported  = true;
                    band.ht_capability = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);

                    if (band.ht_capability & BIT(1)) {
                        width_40 = true;
                    }
                }

                if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) {
                    size_t expected_length = sizeof(band.ht_mcs_set);
                    size_t actual_length   = nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);

                    if (actual_length <= expected_length) {
                        memcpy(band.ht_mcs_set, nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]),
                               actual_length);
                    } else {
                        LOG(DEBUG) << "Invalid length for NL80211_BAND_ATTR_HT_MCS_SET "
                                      "attribute. Expected length: "
                                   << expected_length << ", actual length: " << actual_length;
                    }
                }

                if (tb_band[NL80211_BAND_ATTR_VHT_CAPA]) {
                    band.vht_supported  = true;
                    band.vht_capability = nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]);

                    width_80 = true;

                    switch ((band.vht_capability >> 2) & 3) {
                    case 2:
                        width_80_80 = true;
                        width_160   = true;
                        break;
                    case 1:
                        width_160 = true;
                        break;
                    }
                }

                if (tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]) {
                    size_t expected_length = sizeof(band.vht_mcs_set);
                    size_t actual_length   = nla_len(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);

                    if (actual_length <= expected_length) {
                        memcpy(band.vht_mcs_set, nla_data(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]),
                               actual_length);
                    } else {
                        LOG(DEBUG) << "Invalid length for NL80211_BAND_ATTR_VHT_MCS_SET "
                                      "attribute. Expected length: "
                                   << expected_length << ", actual length: " << actual_length;
                    }
                }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 1)
                // Refer linux/ieee80211.h for each bit representation.
                if (tb_band[NL80211_BAND_ATTR_IFTYPE_DATA]) {
                    band.he_supported = true;

                    // If HE is supported UL and DL-OFDMA are mandatory.
                    band.he_capability = band.he_capability | (3 << 1);

                    const struct nlattr *nl_he_cap = tb_band[NL80211_BAND_ATTR_IFTYPE_DATA];
                    nla_for_each_attr(nl_band, static_cast<struct nlattr *>(nla_data(nl_he_cap)),
                                      nla_len(nl_he_cap), rem_iftype)
                    {
                        nla_parse(tb_iftype, NL80211_BAND_IFTYPE_ATTR_MAX,
                                  static_cast<nlattr *>(nla_data(nl_band)), nla_len(nl_band), NULL);

                        if (tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]) {
                            memcpy(band.he.he_mac_capab_info,
                                   nla_data(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]),
                                   nla_len(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]));
                        }

                        if (tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]) {
                            memcpy(band.he.he_phy_capab_info,
                                   nla_data(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]),
                                   nla_len(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]));

                            /**
			     * check whether the 80_plus_80 and 160 mhz are supported.
			     * if both are supported set 8th and 9th bit.
			     * if only 160 supported set 8th.
			     */
                            switch ((band.he.he_phy_capab_info[0] >> 3) & 3) {
                            case 3:
                                band.he_capability = band.he_capability | (1 << 8);
                                band.he_capability = band.he_capability | (1 << 9);
                                break;
                            case 1:
                                band.he_capability = band.he_capability | (1 << 8);
                                break;
                            }

                            /**
			     * check whether UL_MU_MIMO and UL_MU_MIMO plus OFDMA
			     * are supported.
			     */
                            switch (band.he.he_phy_capab_info[2] >> 6) {
                            case 3:
                                band.he_capability = band.he_capability | (3 << 4);
                                break;
                            case 2:
                                band.he_capability = band.he_capability | (1 << 4);
                                break;
                            case 1:
                                band.he_capability = band.he_capability | (1 << 5);
                                break;
                            default:
                                break;
                            }

                            if (band.he.he_phy_capab_info[3] >> 7) {
                                //set 7th bit if su_beamformer is supported.
                                band.he_capability = band.he_capability | (1 << 7);
                            }

                            if (band.he.he_phy_capab_info[4] & 2) {
                                //set 6th bit if mu_beamformer is supported.
                                band.he_capability = band.he_capability | (1 << 6);
                            }
                            if ((band.he.he_phy_capab_info[6] >> 6) & 1) {
                                //set 3rd bit if DL_MU_MIMO plus OFDMA is supported.
                                band.he_capability = band.he_capability | (1 << 3);
                            }
                        }

                        // According to definition in "linux/iee80211.h" and 9.4.2.248.4 of IEEE P802.11.
                        if (tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]) {
                            int he_rx_nss, he_tx_nss, he_mcs;
                            memcpy(band.he.he_mcs_nss_set,
                                   nla_data(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]),
                                   nla_len(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]));

                            uint16_t he_rx_mcs_map =
                                band.he.he_mcs_nss_set[0] | (band.he.he_mcs_nss_set[1] << 8);
                            for (he_rx_nss = 8; he_rx_nss > 0; he_rx_nss--) {
                                he_mcs = ((he_rx_mcs_map >> (2 * (he_rx_nss - 1))) & 3);

                                // 3 represents HE_MCS_NOT_SUPPORTED
                                if (he_mcs != 3)
                                    break;
                            }

                            band.he_capability = band.he_capability | ((7 & (he_rx_nss - 1)) << 10);

                            uint16_t he_tx_mcs_map =
                                band.he.he_mcs_nss_set[2] | (band.he.he_mcs_nss_set[3] << 8);
                            for (he_tx_nss = 8; he_tx_nss > 0; he_tx_nss--) {
                                he_mcs = ((he_tx_mcs_map >> (2 * (he_tx_nss - 1))) & 3);

                                if (he_mcs != 3)
                                    break;
                            }

                            band.he_capability = band.he_capability | ((7 & (he_tx_nss - 1)) << 13);
                        }

                        if (tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]) {
                            memcpy(band.he.optional,
                                   nla_data(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]),
                                   nla_len(tb_iftype[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]));
                        }
                    }
                }
#endif

                if (!tb_band[NL80211_BAND_ATTR_FREQS]) {
                    return;
                }

                struct nlattr *nl_freq;
                int rem_freq;

                nla = tb_band[NL80211_BAND_ATTR_FREQS];
                nla_for_each_attr(nl_freq, static_cast<struct nlattr *>(nla_data(nla)),
                                  nla_len(nla), rem_freq)
                {
                    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
                    static auto freq_policy = []() {
                        static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1];
                        static bool initialized = false;
                        if (!initialized) {
                            initialized = true;

                            freq_policy[NL80211_FREQUENCY_ATTR_FREQ]         = {NLA_U32, 0, 0};
                            freq_policy[NL80211_FREQUENCY_ATTR_DISABLED]     = {NLA_FLAG, 0, 0};
                            freq_policy[NL80211_FREQUENCY_ATTR_RADAR]        = {NLA_FLAG, 0, 0};
                            freq_policy[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = {NLA_U32, 0, 0};
                        }

                        return freq_policy;
                    };
                    if (nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
                                  static_cast<nlattr *>(nla_data(nl_freq)), nla_len(nl_freq),
                                  freq_policy())) {
                        LOG(ERROR) << "Failed to parse frequency " << nl_freq->nla_type + 1 << "!";
                        return;
                    }

                    // Ignore "channels" that are disabled or with no frequency.
                    if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ] ||
                        tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
                        continue;
                    }

                    uint32_t freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

                    channel_info channel{};
                    channel.center_freq = freq;
                    channel.number      = son::wireless_utils::freq_to_channel(freq);

                    if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) {
                        channel.tx_power =
                            nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) / 100;
                    }

                    if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR]) {
                        channel.is_dfs = true;
                    }

                    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_20MHZ]) {
                        /**
                         * NO_20MHZ will only be set for channels that are limited to 5 or 10MHz,
                         * which is probably not something we will ever want to use.
                         * So we can safely skip a channel that has NO_20MHZ set.
                         */
                        continue;
                    } else {
                        channel.supported_bandwidths.push_back(
                            beerocks::eWiFiBandwidth::BANDWIDTH_20);
                    }
                    if (width_40 && (!tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS] ||
                                     !tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS])) {
                        channel.supported_bandwidths.push_back(
                            beerocks::eWiFiBandwidth::BANDWIDTH_40);
                    }
                    if (width_80 && !tb_freq[NL80211_FREQUENCY_ATTR_NO_80MHZ]) {
                        channel.supported_bandwidths.push_back(
                            beerocks::eWiFiBandwidth::BANDWIDTH_80);
                    }
                    if (width_80_80 && !tb_freq[NL80211_FREQUENCY_ATTR_NO_80MHZ]) {
                        // NL80211_FREQUENCY_ATTR_NO_80MHZ includes 80+80 channels
                        channel.supported_bandwidths.push_back(
                            beerocks::eWiFiBandwidth::BANDWIDTH_80_80);
                    }
                    if (width_160 && !tb_freq[NL80211_FREQUENCY_ATTR_NO_160MHZ]) {
                        // NL80211_FREQUENCY_ATTR_NO_160MHZ does not include 80+80 channels
                        channel.supported_bandwidths.push_back(
                            beerocks::eWiFiBandwidth::BANDWIDTH_160);
                    }

                    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR] ||
                        tb_freq[__NL80211_FREQUENCY_ATTR_NO_IBSS]) {
                        /**
                         * NL80211_FREQUENCY_ATTR_NO_IR superseded NL80211_FREQUENCY_ATTR_NO_IBSS
                         * for legacy kernels we still need to check
                         * __NL80211_FREQUENCY_ATTR_NO_IBSS, for both attributes we use the no_ir.
                         */
                        channel.no_ir = true;
                    }

                    if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
                        auto dfs_state = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);
                        channel.radar_affected =
                            dfs_state == NL80211_DFS_UNAVAILABLE ? true : false;
                        switch (dfs_state) {
                        case NL80211_DFS_USABLE: {
                            channel.dfs_state = beerocks::eDfsState::USABLE;
                            break;
                        }
                        case NL80211_DFS_UNAVAILABLE: {
                            channel.dfs_state = beerocks::eDfsState::UNAVAILABLE;
                            break;
                        }
                        case NL80211_DFS_AVAILABLE: {
                            channel.dfs_state = beerocks::eDfsState::AVAILABLE;
                            break;
                        }
                        default:
                            break;
                        }
                    }

                    //Filter out chanels that are not DFS but still have the NO_IR flag
                    if (!channel.is_dfs && channel.no_ir) {
                        continue;
                    }

                    band.supported_channels[channel.number] = channel;
                }
            }
        });
}

bool nl80211_client_impl::get_sta_info(const std::string &interface_name,
                                       const sMacAddr &sta_mac_address, sta_info &sta_info)
{
    sta_info = {};

    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_STATION, NLM_F_DUMP,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, sta_mac_address.oct);

            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            if (!tb[NL80211_ATTR_STA_INFO]) {
                LOG(ERROR) << "STA stats missing!";
                return;
            }

            // Parse nested station stats
            struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
            static auto stats_policy = []() {
                static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1];
                static bool initialized = false;
                if (!initialized) {
                    initialized = true;

                    stats_policy[NL80211_STA_INFO_INACTIVE_TIME] = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_RX_BYTES]      = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_RX_PACKETS]    = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_TX_BYTES]      = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_TX_PACKETS]    = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_TX_RETRIES]    = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_TX_FAILED]     = {NLA_U32, 0, 0};
                    stats_policy[NL80211_STA_INFO_SIGNAL]        = {NLA_U8, 0, 0};
                    stats_policy[NL80211_STA_INFO_SIGNAL_AVG]    = {NLA_U8, 0, 0};
                    stats_policy[NL80211_STA_INFO_TX_BITRATE]    = {NLA_NESTED, 0, 0};
                    stats_policy[NL80211_STA_INFO_RX_BITRATE]    = {NLA_NESTED, 0, 0};
                }

                return stats_policy;
            };
            if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO],
                                 stats_policy())) {
                LOG(ERROR) << "Failed to parse nested STA attributes!";
                return;
            }

            if (sinfo[NL80211_STA_INFO_INACTIVE_TIME]) {
                sta_info.inactive_time_ms = nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_INACTIVE_TIME attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_RX_BYTES]) {
                sta_info.rx_bytes = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_RX_BYTES attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_RX_PACKETS]) {
                sta_info.rx_packets = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_RX_PACKETS attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_TX_BYTES]) {
                sta_info.tx_bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_TX_BYTES attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_TX_PACKETS]) {
                sta_info.tx_packets = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_TX_PACKETS attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_TX_RETRIES]) {
                sta_info.tx_retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_TX_RETRIES attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_TX_FAILED]) {
                sta_info.tx_failed = nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_TX_FAILED attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_SIGNAL]) {
                sta_info.signal_dbm = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_SIGNAL attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_SIGNAL_AVG]) {
                sta_info.signal_avg_dbm = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_SIGNAL_AVG attribute is missing";
            }

            // Bit rate parsing helper function
            auto parse_bitrate_func = [&](struct nlattr *bitrate_attr, int &rate,
                                          uint8_t &bw) -> void {
                rate = 0;
                bw   = 0;

                struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
                static auto rate_policy = []() {
                    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1];
                    static bool initialized = false;
                    if (!initialized) {
                        initialized = true;

                        rate_policy[NL80211_RATE_INFO_BITRATE]         = {NLA_U16, 0, 0};
                        rate_policy[NL80211_RATE_INFO_BITRATE32]       = {NLA_U32, 0, 0};
                        rate_policy[NL80211_RATE_INFO_40_MHZ_WIDTH]    = {NLA_FLAG, 0, 0};
                        rate_policy[NL80211_RATE_INFO_80_MHZ_WIDTH]    = {NLA_FLAG, 0, 0};
                        rate_policy[NL80211_RATE_INFO_80P80_MHZ_WIDTH] = {NLA_FLAG, 0, 0};
                        rate_policy[NL80211_RATE_INFO_160_MHZ_WIDTH]   = {NLA_FLAG, 0, 0};
                    }

                    return rate_policy;
                };

                if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, bitrate_attr, rate_policy())) {
                    LOG(ERROR) << "Failed to parse nested rate attributes!";
                } else if (rinfo[NL80211_RATE_INFO_BITRATE32]) {
                    rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
                } else if (rinfo[NL80211_RATE_INFO_BITRATE]) {
                    rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                } else {
                    LOG(DEBUG) << "NL80211_RATE_INFO_BITRATE attribute is missing";
                }

                bw = beerocks::BANDWIDTH_20;
                if (rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH]) {
                    bw = beerocks::BANDWIDTH_40;
                } else if (rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH]) {
                    bw = beerocks::BANDWIDTH_80;
                } else if ((rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH]) ||
                           (rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])) {
                    bw = beerocks::BANDWIDTH_160;
                } else if ((rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]) ||
                           (rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH])) {
                    bw = beerocks::BANDWIDTH_UNKNOWN;
                }
            };

            int rate;
            uint8_t bw;
            if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
                parse_bitrate_func(sinfo[NL80211_STA_INFO_TX_BITRATE], rate, bw);
                sta_info.tx_bitrate_100kbps = rate;
                sta_info.dl_bandwidth       = bw;
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_TX_BITRATE attribute is missing";
            }

            if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
                parse_bitrate_func(sinfo[NL80211_STA_INFO_RX_BITRATE], rate, bw);
                sta_info.rx_bitrate_100kbps = rate;
            } else {
                LOG(DEBUG) << "NL80211_STA_INFO_RX_BITRATE attribute is missing";
            }
        });
}

bool nl80211_client_impl::get_survey_info(const std::string &interface_name,
                                          SurveyInfo &survey_info)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_SURVEY, NLM_F_DUMP,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);

            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            if (!tb[NL80211_ATTR_SURVEY_INFO]) {
                LOG(ERROR) << "Survey data missing!";
                return;
            }

            // Parse nested survey info
            struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
            static auto survey_policy = []() {
                static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1];
                static bool initialized = false;
                if (!initialized) {
                    initialized = true;

                    survey_policy[NL80211_SURVEY_INFO_FREQUENCY] = {NLA_U32, 0, 0};
                    survey_policy[NL80211_SURVEY_INFO_NOISE]     = {NLA_U8, 0, 0};
                }

                return survey_policy;
            };
            if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX, tb[NL80211_ATTR_SURVEY_INFO],
                                 survey_policy())) {
                LOG(ERROR) << "Failed to parse nested survey attributes!";
                return;
            }

            sChannelSurveyInfo channel_survey_info;
            channel_survey_info.in_use = sinfo[NL80211_SURVEY_INFO_IN_USE];

            if (sinfo[NL80211_SURVEY_INFO_FREQUENCY]) {
                channel_survey_info.frequency_mhz =
                    nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
            } else {
                LOG(ERROR) << "NL80211_SURVEY_INFO_FREQUENCY attribute is missing";
                return;
            }

            if (sinfo[NL80211_SURVEY_INFO_NOISE]) {
                channel_survey_info.noise_dbm =
                    (int8_t)nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
            } else {
                LOG(TRACE) << "NL80211_SURVEY_INFO_NOISE attribute is missing";
            }

            if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]) {
                channel_survey_info.time_on_ms =
                    nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]);
            }

            if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]) {
                channel_survey_info.time_busy_ms =
                    nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]);
            }

            if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY]) {
                channel_survey_info.time_ext_busy_ms =
                    nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY]);
            }

            if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]) {
                channel_survey_info.time_rx_ms =
                    nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]);
            }

            if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]) {
                channel_survey_info.time_tx_ms =
                    nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]);
            }

            if (sinfo[NL80211_SURVEY_INFO_TIME_SCAN]) {
                channel_survey_info.time_scan_ms =
                    nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_SCAN]);
            }

            survey_info.data.emplace_back(channel_survey_info);
        });
}

bool nl80211_client_impl::set_tx_power_limit(const std::string &interface_name, uint32_t limit)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface '" << interface_name
                   << "': " << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_SET_WIPHY, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING, NL80211_TX_POWER_LIMITED);
            nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, limit * 100); //mBm
            return true;
        },
        [&](struct nl_msg *msg) {});
}

bool nl80211_client_impl::get_tx_power_dbm(const std::string &interface_name, uint32_t &power)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface '" << interface_name
                   << "': " << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_INTERFACE, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            if (!tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) {
                LOG(WARNING) << "Failed to get tx power!";
                return;
            }
            power = nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) * 0.01; // mBm to dBm
        });
}

bool nl80211_client_impl::channel_scan_abort(const std::string &interface_name)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    if (interface_name.empty()) {
        LOG(ERROR) << "interface_name is empty!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface '" << interface_name
                   << "': " << strerror(errno);

        return false;
    }

    return m_socket.get()->send_receive_msg(NL80211_CMD_ABORT_SCAN, 0,
                                            [&](struct nl_msg *msg) -> bool {
                                                nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
                                                return true;
                                            },
                                            [&](struct nl_msg *msg) {});
}

bool nl80211_client_impl::add_key(const std::string &interface_name, const sKeyInfo &key_info)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    if (key_info.key.empty() || key_info.key_seq.empty()) {
        LOG(ERROR) << "Key and key sequences must be provided!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    LOG(DEBUG) << "Adding new key for interface '" << interface_name << "'." << std::endl
               << "Key index: " << key_info.key_idx << " MAC: " << key_info.mac
               << " Key cipher: " << key_info.key_cipher;

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_NEW_KEY, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_info.key_idx);

            // If there is a MAC address, it's a pairwise key. If not,
            // it's a group key.
            if (key_info.mac != beerocks::net::network_utils::ZERO_MAC) {
                LOG(DEBUG) << "Adding a pairwise key.";
                nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, key_info.mac.oct);
                nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_PAIRWISE);
            } else {
                LOG(DEBUG) << "Adding a group key.";
                nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
            }
            nla_put(msg, NL80211_ATTR_KEY_DATA, key_info.key.size(), key_info.key.data());
            nla_put(msg, NL80211_ATTR_KEY_SEQ, key_info.key_seq.size(), key_info.key_seq.data());
            nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, key_info.key_cipher);

            return true;
        },
        [&](struct nl_msg *msg) {});
}

bool nl80211_client_impl::add_station(const std::string &interface_name, const sMacAddr &mac,
                                      assoc_frame::AssocReqFrame &assoc_req, uint16_t aid)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    LOG(DEBUG) << "Adding station with MAC : '" << tlvf::mac_to_string(mac) << "'.";

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_NEW_STATION, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac.oct);
            nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, assoc_req.listen_interval());
            nla_put(msg, NL80211_ATTR_STA_SUPPORTED_RATES, assoc_req.supported_rates_length(),
                    assoc_req.supported_rates());
            nla_put_u16(msg, NL80211_ATTR_STA_AID, aid);

            // TODO: PPM-2349: add station capabilities
            return true;
        },
        [&](struct nl_msg *msg) {});
}

bool nl80211_client_impl::get_key(const std::string &interface_name, sKeyInfo &key_info)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    LOG(DEBUG) << "Getting key with index '" << key_info.key_idx << "' for MAC '"
               << tlvf::mac_to_string(key_info.mac) << "'";

    return m_socket.get()->send_receive_msg(
        NL80211_CMD_GET_KEY, 0,
        [&](struct nl_msg *msg) -> bool {
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
            nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_info.key_idx);

            // If there is a MAC address, it's a pairwise key. If not,
            // it's a group key.
            if (key_info.mac != beerocks::net::network_utils::ZERO_MAC) {
                LOG(DEBUG) << "Getting a pairwise key";
                nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, key_info.mac.oct);
                nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_PAIRWISE);
            } else {
                LOG(DEBUG) << "Getting a group key";
                nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
            }
            return true;
        },
        [&](struct nl_msg *msg) {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = static_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));

            // Parse the netlink message
            if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                          NULL)) {
                LOG(ERROR) << "Failed to parse netlink message!";
                return;
            }

            if (!tb[NL80211_ATTR_KEY_IDX]) {
                LOG(ERROR) << "Key index missing!";
                return;
            }

            if (!tb[NL80211_ATTR_KEY_DATA]) {
                LOG(ERROR) << "Key data missing!";
                return;
            }

            const auto &key_data = static_cast<uint8_t *>(nla_data(tb[NL80211_ATTR_KEY_DATA]));
            const auto key_len   = nla_len(tb[NL80211_ATTR_KEY_DATA]);
            key_info.key.insert(key_info.key.begin(), key_data, key_data + key_len);

            if (!tb[NL80211_ATTR_KEY_SEQ]) {
                LOG(ERROR) << "Key sequence missing!";
                return;
            }

            const auto &seq_data = static_cast<uint8_t *>(nla_data(tb[NL80211_ATTR_KEY_SEQ]));
            const auto seq_len   = nla_len(tb[NL80211_ATTR_KEY_SEQ]);
            key_info.key_seq.insert(key_info.key_seq.begin(), seq_data, seq_data + seq_len);
            key_info.key_cipher = nla_get_u32(tb[NL80211_ATTR_KEY_CIPHER]);
        });
}

bool nl80211_client_impl::send_delba(const std::string &interface_name, const sMacAddr &dst,
                                     const sMacAddr &src, const sMacAddr &bssid)
{
    if (!m_socket) {
        LOG(ERROR) << "Socket is NULL!";
        return false;
    }

    // Get the interface index for given interface name
    int iface_index = if_nametoindex(interface_name.c_str());
    if (0 == iface_index) {
        LOG(ERROR) << "Failed to read the index of interface " << interface_name << ": "
                   << strerror(errno);

        return false;
    }

    // Create the MAC header that we will include as an attribute:
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx{tx_buffer, sizeof(tx_buffer)};

    auto mac_header = std::make_shared<ieee80211::sMacHeader>(tx_buffer, sizeof(tx_buffer));
    if (!mac_header->isInitialized()) {
        LOG(ERROR) << "Failed to create sMacHeader!";
        return false;
    }

    mac_header->frame_control_b1().type = static_cast<uint8_t>(ieee80211::sMacHeader::eType::MGMT);
    mac_header->frame_control_b1().subtype = static_cast<uint8_t>(ieee80211::sMacHeader::eSubtypeMgmt::ACTION);
    mac_header->addr1() = dst;
    mac_header->addr2() = src;
    mac_header->addr3() = bssid;

    constexpr uint8_t action_fields[] = {
        0x03, // Block ack
        0x02, // Delba
        0x80, // Initiator and TID
        0x08, // Reserved
        0x25, // Reason code (STA does not want to use the mechanism)
        0x00  // Reason code
    };

    // Initialize frame_attr with the MAC header
    std::vector<uint8_t> frame_attr = {cmdu_tx.getMessageBuff(),
                                       cmdu_tx.getMessageBuff() + mac_header->getLen()};

    // add the action fields:
    frame_attr.insert(frame_attr.end(), std::begin(action_fields), std::end(action_fields));

    LOG(DEBUG) << "Sending DELBA frame on interface '" << interface_name << "' to MAC '" << dst
               << "' with source '" << src << "' bssid '" << bssid << "'";
    return m_socket.get()->send_receive_msg(NL80211_CMD_FRAME, 0,
                                            [&](struct nl_msg *msg) -> bool {
                                                nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
                                                nla_put(msg, NL80211_ATTR_FRAME, frame_attr.size(),
                                                        frame_attr.data());
                                                return true;
                                            },
                                            [&](struct nl_msg *msg) {});
}

} // namespace bwl
