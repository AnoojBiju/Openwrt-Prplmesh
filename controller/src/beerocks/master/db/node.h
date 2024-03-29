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

    beerocks::eType get_type();
    bool set_type(beerocks::eType type_);

    const std::string mac;           // client
    std::string parent_mac;          // hostap
    std::string previous_parent_mac; //hostap

    beerocks::WifiChannel wifi_channel;

    std::string ipv4;
    std::string name;
    int hierarchy = -1; //redundant but more efficient
    beerocks::message::sRadioCapabilities *capabilities;

    beerocks::eNodeState state = beerocks::STATE_DISCONNECTED;

    bool supports_6ghz             = true;
    int failed_6ghz_steer_attempts = 0;

    bool supports_5ghz             = true;
    int failed_5ghz_steer_attempts = 0;

    bool supports_24ghz             = true;
    int failed_24ghz_steer_attempts = 0;

    std::chrono::steady_clock::time_point last_state_change;

    int load_balancer_task_id             = -1;
    int dynamic_channel_selection_task_id = -1;
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
