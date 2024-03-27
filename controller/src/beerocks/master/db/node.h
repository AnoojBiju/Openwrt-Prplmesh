/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _NODE_H_
#define _NODE_H_

#include "../tasks/task.h"
#include <bcl/beerocks_wifi_channel.h>
#include <bcl/network/network_utils.h>
#include <tlvf/common/sMacAddr.h>
#include <tlvf/ieee_1905_1/tlvReceiverLinkMetric.h>
#include <tlvf/ieee_1905_1/tlvTransmitterLinkMetric.h>
#include <tlvf/wfa_map/tlvApMetrics.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>

#include <list>
#include <map>
#include <unordered_set>

namespace son {

typedef struct {
    std::string mac;
    std::string ssid;
    bool backhaul_vap;
} sVapElement;

class node {
public:
    node(beerocks::eType type_, const std::string &mac_);
    void clear_node_stats_info();

    beerocks::eType get_type();
    bool set_type(beerocks::eType type_);

    int8_t vap_id = beerocks::IFACE_ID_INVALID;
    const std::string mac;           // client
    std::string parent_mac;          // hostap
    std::string previous_parent_mac; //hostap

    beerocks::WifiChannel wifi_channel;

    std::string ipv4;
    std::string name;
    int hierarchy = -1; //redundant but more efficient
    beerocks::message::sRadioCapabilities *capabilities;
    beerocks::message::sRadioCapabilities m_sta_6ghz_capabilities;
    beerocks::message::sRadioCapabilities m_sta_5ghz_capabilities;
    beerocks::message::sRadioCapabilities m_sta_24ghz_capabilities;

    beerocks::eNodeState state = beerocks::STATE_DISCONNECTED;

    bool supports_6ghz            = true;
    int failed_6ghz_steer_attemps = 0;

    bool supports_5ghz            = true;
    int failed_5ghz_steer_attemps = 0;

    bool supports_24ghz            = true;
    int failed_24ghz_steer_attemps = 0;

    std::chrono::steady_clock::time_point last_state_change;

    int load_balancer_task_id             = -1;
    int dynamic_channel_selection_task_id = -1;

    class sta_stats_params {
    public:
        uint32_t rx_packets                             = 0;
        uint32_t tx_packets                             = 0;
        uint32_t rx_bytes                               = 0;
        uint32_t tx_bytes                               = 0;
        uint32_t retrans_count                          = 0;
        uint8_t tx_load_percent                         = 0;
        uint8_t rx_load_percent                         = 0;
        uint16_t rx_phy_rate_100kb                      = 0;
        uint16_t tx_phy_rate_100kb                      = 0;
        int8_t rx_rssi                                  = beerocks::RSSI_INVALID;
        uint16_t stats_delta_ms                         = 0;
        std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
    };
    std::shared_ptr<sta_stats_params> stats_info = std::make_shared<sta_stats_params>();

    class radio {
    public:
        std::unordered_map<int8_t, sVapElement> vaps_info;
    };
    std::shared_ptr<radio> hostap = std::make_shared<radio>();

    beerocks::eIfaceType iface_type = beerocks::IFACE_TYPE_ETHERNET;
    std::chrono::steady_clock::time_point last_seen;

private:
    beerocks::eType type;
};
} // namespace son
#endif
