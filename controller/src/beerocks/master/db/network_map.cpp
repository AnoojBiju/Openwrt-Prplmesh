/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "network_map.h"

#include <bcl/beerocks_utils.h>
#include <bcl/beerocks_wifi_channel.h>
#include <bcl/network/network_utils.h>
#include <easylogging++.h>

#include <beerocks/tlvf/beerocks_message.h>
#include <beerocks/tlvf/beerocks_message_bml.h>

#include <bml_defs.h>

#include "../controller.h"

#include <unordered_set>

using namespace beerocks;
using namespace net;
using namespace son;

void network_map::send_bml_network_map_message(db &database, int fd,
                                               ieee1905_1::CmduMessageTx &cmdu_tx, uint16_t id)
{
    auto controller_ctx = database.get_controller_ctx();
    if (!controller_ctx) {
        LOG(ERROR) << "controller_ctx == nullptr";
        return;
    }

    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_NW_MAP_RESPONSE>(cmdu_tx, id);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_NW_MAP_BRIDGE_RESPONSE message!";
        return;
    }

    auto beerocks_header = message_com::get_beerocks_header(cmdu_tx);

    if (!beerocks_header) {
        LOG(ERROR) << "Failed getting beerocks_header!";
        return;
    }

    beerocks_header->actionhdr()->last() = 0;

    uint8_t *data_start = nullptr;

    std::ptrdiff_t size = 0, size_left = 0, node_len = 0;
    response->node_num() = 0;

    auto send_nw_map_message_if_needed = [&]() -> bool {
        if (node_len > size_left) {
            if (response->node_num() == 0) {
                LOG(ERROR) << "node size is bigger than buffer size";
                return false;
            }

            controller_ctx->send_cmdu(fd, cmdu_tx);

            response =
                message_com::create_vs_message<beerocks_message::cACTION_BML_NW_MAP_RESPONSE>(
                    cmdu_tx, id);

            if (response == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            beerocks_header                      = message_com::get_beerocks_header(cmdu_tx);
            beerocks_header->actionhdr()->last() = 0;
            response->node_num()                 = 0;
            data_start                           = nullptr;
            size                                 = 0;
        }
        return true;
    };

    for (const auto &agent_pair : database.m_agents) {
        const auto &agent = agent_pair.second;
        LOG(ERROR) << "Parsing agent " << agent->al_mac;
        if (agent->state != beerocks::STATE_CONNECTED) {
            LOG(DEBUG) << "Agent: " << agent->al_mac << " not connected, continue";
            continue;
        }
        node_len  = sizeof(BML_NODE);
        size_left = beerocks_header->getMessageBuffLength() - beerocks_header->getMessageLength();

        if (!send_nw_map_message_if_needed()) {
            return;
        }

        if (!response->alloc_buffer(node_len)) {
            LOG(ERROR) << "Failed allocating buffer!";
            return;
        }

        if (data_start == nullptr) {
            data_start = reinterpret_cast<uint8_t *>(response->buffer(0));
        }

        fill_bml_agent_data(database, agent, data_start + size, size_left);

        response->node_num()++;
        size += node_len;

        for (const auto &radio : agent->radios) {
            for (const auto &bss : radio.second->bsses) {
                for (const auto &station_pair : bss.second->connected_stations) {
                    const auto &station = station_pair.second;
                    LOG(ERROR) << "Handling station " << station->mac;
                    if (station->state != beerocks::STATE_CONNECTED) {
                        LOG(ERROR) << "State not connected for STA " << station->mac;
                        continue;
                    }
                    node_len  = sizeof(BML_NODE) - sizeof(BML_NODE::N_DATA::N_GW_IRE);
                    size_left = beerocks_header->getMessageBuffLength() -
                                beerocks_header->getMessageLength();

                    if (!send_nw_map_message_if_needed()) {
                        return;
                    }

                    if (!response->alloc_buffer(node_len)) {
                        LOG(ERROR) << "Failed allocating buffer!";
                        return;
                    }

                    if (data_start == nullptr) {
                        data_start = reinterpret_cast<uint8_t *>(response->buffer(0));
                    }

                    fill_bml_station_data(database, station, data_start + size, size_left);

                    response->node_num()++;
                    size += node_len;
                }
            }
        }
    }

    beerocks_header->actionhdr()->last() = 1;
    controller_ctx->send_cmdu(fd, cmdu_tx);
}

std::ptrdiff_t network_map::fill_bml_node_data(db &database, std::string node_mac,
                                               uint8_t *tx_buffer,
                                               const std::ptrdiff_t &buffer_size,
                                               bool force_client_disconnect)
{
    std::shared_ptr<Agent> agent = database.get_agent(tlvf::mac_from_string(node_mac));
    if (agent) {
        return fill_bml_agent_data(database, agent, tx_buffer, buffer_size,
                                   force_client_disconnect);
    }

    std::shared_ptr<Station> station = database.get_station(tlvf::mac_from_string(node_mac));
    if (station) {
        return fill_bml_station_data(database, station, tx_buffer, buffer_size,
                                     force_client_disconnect);
    }
    return 0;
}

auto process_backhaul = [](db &database, std::shared_ptr<Station> backhaul, BML_NODE *node,
                           bool is_gateway) {
    if (backhaul) {
        if (backhaul->get_bss()) {
            tlvf::mac_from_string(node->parent_bssid,
                                  tlvf::mac_to_string(backhaul->get_bss()->bssid));
            tlvf::mac_from_string(node->parent_bridge,
                                  tlvf::mac_to_string(database.get_radio_parent_agent(
                                      backhaul->get_bss()->radio.radio_uid)));

            if (!is_gateway) {
                auto parent_backhaul_wifi_channel =
                    database.get_radio_wifi_channel(backhaul->get_bss()->radio.radio_uid);
                if (parent_backhaul_wifi_channel.is_empty()) {
                    LOG(WARNING) << "empty wifi channel of "
                                 << backhaul->get_bss()->radio.radio_uid;
                }

                node->channel   = parent_backhaul_wifi_channel.get_channel();
                node->bw        = parent_backhaul_wifi_channel.get_bandwidth();
                node->freq_type = parent_backhaul_wifi_channel.get_freq_type();
                node->channel_ext_above_secondary =
                    parent_backhaul_wifi_channel.get_ext_above_secondary();
            }
        } else if (backhaul->get_eth_switch()) {
            tlvf::mac_from_string(node->parent_bssid,
                                  tlvf::mac_to_string(backhaul->get_eth_switch()->mac));
            tlvf::mac_from_string(node->parent_bridge,
                                  tlvf::mac_to_string(database.get_eth_switch_parent_agent(
                                      backhaul->get_eth_switch()->mac)));
        }
    }
};

std::ptrdiff_t network_map::fill_bml_station_data(db &database, std::shared_ptr<Station> station,
                                                  uint8_t *tx_buffer,
                                                  const std::ptrdiff_t &buffer_size,
                                                  bool force_client_disconnect)
{
    auto node = (BML_NODE *)tx_buffer;
    if (!station) {
        LOG(ERROR) << "invalid station";
        return 0;
    }

    std::ptrdiff_t node_len = sizeof(BML_NODE) - sizeof(BML_NODE::N_DATA::N_GW_IRE);
    if (node_len > buffer_size) {
        return 0;
    }
    memset(node, 0, node_len);
    node->type = BML_NODE_TYPE_CLIENT;

    if (force_client_disconnect) {
        node->state = BML_NODE_STATE_DISCONNECTED;
    } else {
        switch (station->state) {
        case beerocks::STATE_DISCONNECTED:
            node->state = BML_NODE_STATE_DISCONNECTED;
            break;

        case beerocks::STATE_CONNECTING:
            node->state = BML_NODE_STATE_CONNECTING;
            break;

        case beerocks::STATE_CONNECTED:
            node->state = BML_NODE_STATE_CONNECTED;
            break;

        default:
            node->state = BML_NODE_STATE_UNKNOWN;
        }
    }

    if (station->wifi_channel.is_empty()) {
        LOG(WARNING) << "wifi channel is empty";
    }
    node->channel                     = station->wifi_channel.get_channel();
    node->bw                          = station->wifi_channel.get_bandwidth();
    node->freq_type                   = station->wifi_channel.get_freq_type();
    node->channel_ext_above_secondary = station->wifi_channel.get_ext_above_secondary();

    tlvf::mac_to_array(station->mac, node->mac);

    // remote bridge
    std::shared_ptr<Agent::sRadio::sBss> parent_bss = station->get_bss();
    if (parent_bss) {
        std::shared_ptr<Agent> parent_agent =
            database.get_agent_by_radio_uid(parent_bss->radio.radio_uid);
        if (parent_agent) {
            tlvf::mac_to_array(parent_agent->al_mac, node->parent_bridge);
        }
        tlvf::mac_to_array(parent_bss->bssid, node->parent_bssid);
    }

    node->rx_rssi = database.get_sta_load_rx_rssi(tlvf::mac_to_string(station->mac));

    network_utils::ipv4_from_string(node->ip_v4, station->ipv4);
    string_utils::copy_string(node->name, station->name.c_str(), sizeof(node->name));

    return node_len;
}

std::ptrdiff_t network_map::fill_bml_agent_data(db &database, std::shared_ptr<Agent> agent,
                                                uint8_t *tx_buffer,
                                                const std::ptrdiff_t &buffer_size,
                                                bool force_client_disconnect)
{
    auto node = (BML_NODE *)tx_buffer;

    if (!agent) {
        LOG(ERROR) << "invalid agent";
        return 0;
    }

    std::ptrdiff_t node_len = sizeof(BML_NODE);
    if (node_len > buffer_size) {
        LOG(ERROR) << "buffer overflow!";
        return 0;
    }
    memset(node, 0, node_len);

    node->type = agent->is_gateway ? BML_NODE_TYPE_GW : BML_NODE_TYPE_IRE;

    if (force_client_disconnect) {
        node->state = BML_NODE_STATE_DISCONNECTED;
    } else {
        switch (agent->state) {
        case beerocks::STATE_DISCONNECTED:
            node->state = BML_NODE_STATE_DISCONNECTED;
            break;

        case beerocks::STATE_CONNECTING:
            node->state = BML_NODE_STATE_CONNECTING;
            break;

        case beerocks::STATE_CONNECTED:
            node->state = BML_NODE_STATE_CONNECTED;
            break;

        default:
            node->state = BML_NODE_STATE_UNKNOWN;
        }
    }

    tlvf::mac_from_string(node->mac, tlvf::mac_to_string(agent->al_mac));

    // remote bridge
    tlvf::mac_from_string(node->data.gw_ire.backhaul_mac, tlvf::mac_to_string(agent->parent_mac));

    process_backhaul(database, database.get_station(agent->parent_mac), node, agent->is_gateway);

    network_utils::ipv4_from_string(node->ip_v4, agent->ipv4);
    string_utils::copy_string(node->name, agent->name.c_str(), sizeof(node->name));

    size_t i = 0;
    for (const auto &radio : agent->radios) {
        if (i >= beerocks::utils::array_length(node->data.gw_ire.radio)) {
            LOG(ERROR) << "exceeded size of data.gw_ire.radio[]";
            break;
        }
        tlvf::mac_to_array(radio.first, node->data.gw_ire.radio[i].radio_mac);
        //Useful for scenarios where radio mac address and the station interface mac address are same.
        process_backhaul(database, database.get_station(radio.first), node, agent->is_gateway);

        unsigned vap_id = 0;
        for (const auto &bss : radio.second->bsses) {
            if (bss.second->get_vap_id() >= 0) {
                // If vap_id is set, use it. Normally if one BSS has vap_id set, all of them
                // should have it set. Still, we increment vap_id at the end of the loop so we
                // can deal with unset vap_id as well.
                vap_id = bss.second->get_vap_id();
            }
            if (vap_id >= beerocks::utils::array_length(node->data.gw_ire.radio[i].vap)) {
                LOG(ERROR) << "exceeded size of data.gw_ire.radio[i].vap[] on " << radio.first;
                break;
            }
            tlvf::mac_to_array(bss.first, node->data.gw_ire.radio[i].vap[vap_id].bssid);
            string_utils::copy_string(node->data.gw_ire.radio[i].vap[vap_id].ssid,
                                      bss.second->ssid.c_str(),
                                      sizeof(node->data.gw_ire.radio[i].vap[0].ssid));
            node->data.gw_ire.radio[i].vap[vap_id].backhaul_vap = bss.second->backhaul;
            vap_id++;
        }

        if (radio.second->state == beerocks::STATE_CONNECTED) {

            // Copy the interface name
            string_utils::copy_string(node->data.gw_ire.radio[i].iface_name,
                                      database.get_radio_iface_name(radio.first).c_str(),
                                      BML_NODE_IFACE_NAME_LEN);

            // Radio Vendor
            switch (database.get_radio_iface_type(radio.first)) {
            case beerocks::eIfaceType::IFACE_TYPE_WIFI_INTEL:
                node->data.gw_ire.radio[i].vendor = BML_WLAN_VENDOR_INTEL;
                break;
            default:
                node->data.gw_ire.radio[i].vendor = BML_WLAN_VENDOR_UNKNOWN;
            }

            node->data.gw_ire.radio[i].channel = (radio.second->wifi_channel.is_empty())
                                                     ? 255
                                                     : radio.second->wifi_channel.get_channel();
            node->data.gw_ire.radio[i].cac_completed = radio.second->cac_completed;
            node->data.gw_ire.radio[i].bw            = radio.second->wifi_channel.get_bandwidth();
            node->data.gw_ire.radio[i].freq_type     = radio.second->wifi_channel.get_freq_type();
            node->data.gw_ire.radio[i].channel_ext_above_secondary =
                radio.second->wifi_channel.get_ext_above_secondary();
            node->data.gw_ire.radio[i].ap_active = radio.second->active;

            // Copy the radio identifier string
            tlvf::mac_from_string(node->data.gw_ire.radio[i].radio_identifier,
                                  tlvf::mac_to_string(radio.first));

            ++i;
        }
    }
    return node_len;
}

void network_map::send_bml_nodes_statistics_message_to_listeners(
    db &database, ieee1905_1::CmduMessageTx &cmdu_tx, const std::vector<int> &bml_listeners,
    std::set<std::string> valid_hostaps)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_STATS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    auto beerocks_header = message_com::get_beerocks_header(cmdu_tx);
    if (!beerocks_header) {
        LOG(ERROR) << "Failed getting beerocks_header!";
        return;
    }
    beerocks_header->actionhdr()->last() = 0;

    uint8_t *data_start = nullptr;
    std::ptrdiff_t size = 0, size_left = 0, node_len = 0;

    const auto reserved_size =
        message_com::get_vs_cmdu_size_on_buffer<beerocks_message::cACTION_BML_STATS_UPDATE>();

    // Save room in the output buffer for the number of transmitted nodes
    response->num_of_stats_bulks() = 0;

    // common function definition ///////////////////////////////////////////////
    auto send_if_needed = [&](std::ptrdiff_t &size, std::ptrdiff_t &size_left, size_t &node_size,
                              const uint16_t reserved_size, uint8_t *&data_start) -> bool {
        size_left = cmdu_tx.getMessageBuffLength() - reserved_size - size;

        if ((std::ptrdiff_t)node_size > size_left) {
            if (response->num_of_stats_bulks() == 0) {
                LOG(ERROR) << "node size is bigger than buffer size";
                return false;
            }

            // sending to all listeners
            send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);

            // prepare for next message
            response =
                message_com::create_vs_message<beerocks_message::cACTION_BML_STATS_UPDATE>(cmdu_tx);

            if (response == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            beerocks_header                      = message_com::get_beerocks_header(cmdu_tx);
            beerocks_header->actionhdr()->last() = 0;
            response->num_of_stats_bulks()       = 0;
            size                                 = 0;
        }

        response->alloc_buffer(node_size);

        if (data_start == nullptr) {
            data_start = (uint8_t *)response->buffer(0);
        }
        return true;
    };
    /////////////////////////////////////////////////////////////////////////

    // nodes iterating
    for (const auto &radio_mac : valid_hostaps) {
        std::shared_ptr<Agent::sRadio> radio =
            database.get_radio_by_uid(tlvf::mac_from_string(radio_mac));
        if (!radio) {
            LOG(ERROR) << "invalid radio " << radio_mac;
            continue;
        }
        if (radio->state == beerocks::STATE_CONNECTED) {
            size_t node_size =
                sizeof(BML_STATS) - sizeof(BML_STATS::S_TYPE) + sizeof(BML_STATS::S_TYPE::S_RADIO);
            if (!send_if_needed(size, size_left, node_size, reserved_size, data_start)) {
                return;
            }
            fill_bml_radio_statistics(database, radio, data_start + size, size_left);
            response->num_of_stats_bulks()++;
            size += node_len;

            // sta's
            for (const auto &bss : radio->bsses) {
                for (const auto &sta : bss.second->connected_stations) {
                    if (sta.second->state == beerocks::STATE_CONNECTED) {
                        node_size = sizeof(BML_STATS) - sizeof(BML_STATS::S_TYPE) +
                                    sizeof(BML_STATS::S_TYPE::S_CLIENT);
                        if (!send_if_needed(size, size_left, node_size, reserved_size,
                                            data_start)) {
                            return;
                        }

                        fill_bml_station_statistics(database, sta.second, data_start + size,
                                                    size_left);
                        response->num_of_stats_bulks()++;
                        size += node_len;
                    }
                }
            }
        }
    }

    // sending to all listeners
    beerocks_header->actionhdr()->last() = 1;
    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_event_to_listeners(db &database, ieee1905_1::CmduMessageTx &cmdu_tx,
                                              const std::vector<int> &bml_listeners)
{
    auto controller_ctx = database.get_controller_ctx();
    if (!controller_ctx) {
        LOG(ERROR) << "controller_ctx == nullptr";
        return;
    }

    for (int fd : bml_listeners) {
        controller_ctx->send_cmdu(fd, cmdu_tx);
    }
}

void network_map::send_bml_bss_tm_req_message_to_listeners(db &database,
                                                           ieee1905_1::CmduMessageTx &cmdu_tx,
                                                           const std::vector<int> &bml_listeners,
                                                           std::string target_bssid,
                                                           uint8_t disassoc_imminent)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_BSS_TM_REQ))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_BSS_TM_REQ;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_bss_tm_req = (BML_EVENT_BSS_TM_REQ *)event->data;
    tlvf::mac_from_string(event_bss_tm_req->target_bssid, target_bssid);
    event_bss_tm_req->disassoc_imminent = disassoc_imminent;

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_bh_roam_req_message_to_listeners(db &database,
                                                            ieee1905_1::CmduMessageTx &cmdu_tx,
                                                            const std::vector<int> &bml_listeners,
                                                            std::string bssid, uint8_t channel)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_BH_ROAM_REQ))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_BH_ROAM_REQ;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_bh_roam_req = (BML_EVENT_BH_ROAM_REQ *)event->data;
    tlvf::mac_from_string(event_bh_roam_req->bssid, bssid);
    event_bh_roam_req->channel = channel;

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_client_allow_req_message_to_listeners(
    db &database, ieee1905_1::CmduMessageTx &cmdu_tx, const std::vector<int> &bml_listeners,
    std::string sta_mac, std::string hostap_mac, std::string ip)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_CLIENT_ALLOW_REQ))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_CLIENT_ALLOW_REQ;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_client_allow_req = (BML_EVENT_CLIENT_ALLOW_REQ *)event->data;
    tlvf::mac_from_string(event_client_allow_req->sta_mac, sta_mac);
    tlvf::mac_from_string(event_client_allow_req->hostap_mac, hostap_mac);
    network_utils::ipv4_from_string(event_client_allow_req->ip, ip);

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_client_disallow_req_message_to_listeners(
    db &database, ieee1905_1::CmduMessageTx &cmdu_tx, const std::vector<int> &bml_listeners,
    std::string sta_mac, std::string hostap_mac)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_CLIENT_DISALLOW_REQ))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_CLIENT_DISALLOW_REQ;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_client_disallow_req = (BML_EVENT_CLIENT_DISALLOW_REQ *)event->data;
    tlvf::mac_from_string(event_client_disallow_req->sta_mac, sta_mac);
    tlvf::mac_from_string(event_client_disallow_req->hostap_mac, hostap_mac);

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_acs_start_message_to_listeners(db &database,
                                                          ieee1905_1::CmduMessageTx &cmdu_tx,
                                                          const std::vector<int> &bml_listeners,
                                                          std::string hostap_mac)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_ACS_START))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_ACS_START;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_acs_start = (BML_EVENT_ACS_START *)event->data;

    tlvf::mac_from_string(event_acs_start->hostap_mac, hostap_mac);

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_csa_notification_message_to_listeners(
    db &database, ieee1905_1::CmduMessageTx &cmdu_tx, const std::vector<int> &bml_listeners,
    std::string hostap_mac, uint8_t bandwidth, uint8_t channel, uint8_t channel_ext_above_primary,
    uint16_t vht_center_frequency)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_CSA_NOTIFICATION))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_CSA_NOTIFICATION;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_csa_notification = (BML_EVENT_CSA_NOTIFICATION *)event->data;
    tlvf::mac_from_string(event_csa_notification->hostap_mac, hostap_mac);
    event_csa_notification->bandwidth                 = bandwidth;
    event_csa_notification->channel                   = channel;
    event_csa_notification->channel_ext_above_primary = channel_ext_above_primary;
    event_csa_notification->vht_center_frequency      = vht_center_frequency;

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

void network_map::send_bml_cac_status_changed_notification_message_to_listeners(
    db &database, ieee1905_1::CmduMessageTx &cmdu_tx, const std::vector<int> &bml_listeners,
    std::string hostap_mac, uint8_t cac_completed)
{
    auto response =
        message_com::create_vs_message<beerocks_message::cACTION_BML_EVENTS_UPDATE>(cmdu_tx);
    if (response == nullptr) {
        LOG(ERROR) << "Failed building ACTION_BML_STATS_UPDATE message!";
        return;
    }

    if (!response->alloc_buffer(sizeof(BML_EVENT) +
                                sizeof(BML_EVENT_CAC_STATUS_CHANGED_NOTIFICATION))) {
        LOG(ERROR) << "Failed to alloc buffer";
        return;
    }

    auto event = reinterpret_cast<BML_EVENT *>(response->buffer(0));
    if (event == nullptr) {
        LOG(ERROR) << "event is nullptr";
        return;
    }

    event->type = BML_EVENT_TYPE_CAC_STATUS_CHANGED_NOTIFICATION;
    event->data = response->buffer(sizeof(BML_EVENT));

    auto event_cac_status_changed = (BML_EVENT_CAC_STATUS_CHANGED_NOTIFICATION *)event->data;
    tlvf::mac_from_string(event_cac_status_changed->hostap_mac, hostap_mac);
    event_cac_status_changed->cac_completed = cac_completed;

    send_bml_event_to_listeners(database, cmdu_tx, bml_listeners);
}

std::ptrdiff_t network_map::fill_bml_radio_statistics(db &database,
                                                      std::shared_ptr<Agent::sRadio> radio,
                                                      uint8_t *tx_buffer, std::ptrdiff_t buf_size)
{
    if (!radio) {
        LOG(ERROR) << "invalid radio";
        return 0;
    }
    std::ptrdiff_t stats_bulk_len =
        sizeof(BML_STATS) - sizeof(BML_STATS::S_TYPE) + sizeof(BML_STATS::S_TYPE::S_RADIO);
    ;

    if (stats_bulk_len > buf_size) {
        return 0;
    }

    //prepearing buffer and calc size
    auto radio_stats_bulk = (BML_STATS *)tx_buffer;

    //fill radio stats
    memset(radio_stats_bulk, 0, stats_bulk_len);
    tlvf::mac_to_array(radio->radio_uid, radio_stats_bulk->mac);
    radio_stats_bulk->type = BML_STAT_TYPE_RADIO;

    radio_stats_bulk->bytes_sent              = radio->stats_info->tx_bytes;
    radio_stats_bulk->bytes_received          = radio->stats_info->rx_bytes;
    radio_stats_bulk->packets_sent            = radio->stats_info->tx_packets;
    radio_stats_bulk->packets_received        = radio->stats_info->rx_packets;
    radio_stats_bulk->measurement_window_msec = radio->stats_info->stats_delta_ms;

    radio_stats_bulk->errors_sent       = radio->stats_info->errors_sent;
    radio_stats_bulk->errors_received   = radio->stats_info->errors_received;
    radio_stats_bulk->retrans_count     = radio->stats_info->retrans_count;
    radio_stats_bulk->uType.radio.noise = radio->stats_info->noise;

    radio_stats_bulk->uType.radio.bss_load = radio->stats_info->channel_load_percent;

    return stats_bulk_len;
}

std::ptrdiff_t network_map::fill_bml_station_statistics(db &database, std::shared_ptr<Station> pSta,
                                                        uint8_t *tx_buffer, std::ptrdiff_t buf_size)
{
    if (!pSta) {
        LOG(ERROR) << "invalid station";
        return 0;
    }
    std::ptrdiff_t stats_bulk_len =
        sizeof(BML_STATS) - sizeof(BML_STATS::S_TYPE) + sizeof(BML_STATS::S_TYPE::S_CLIENT);

    if (stats_bulk_len > buf_size) {
        return 0;
    }

    // filter client which have not been measured yet
    if (pSta->stats_info->rx_rssi == beerocks::RSSI_INVALID) {
        //LOG(DEBUG) << "sta_mac=" << n->mac << ", signal_strength=INVALID!";
        return buf_size;
    }

    //prepearing buffer and calc size
    auto sta_stats_bulk = (BML_STATS *)tx_buffer;

    //fill sta stats
    //memset(sta_stats_bulk, 0, stats_bulk_len);
    tlvf::mac_from_string(sta_stats_bulk->mac, tlvf::mac_to_string(pSta->mac));
    sta_stats_bulk->type = BML_STAT_TYPE_CLIENT;

    sta_stats_bulk->bytes_sent              = pSta->stats_info->tx_bytes;
    sta_stats_bulk->bytes_received          = pSta->stats_info->rx_bytes;
    sta_stats_bulk->packets_sent            = pSta->stats_info->tx_packets;
    sta_stats_bulk->packets_received        = pSta->stats_info->rx_packets;
    sta_stats_bulk->measurement_window_msec = pSta->stats_info->stats_delta_ms;
    sta_stats_bulk->retrans_count           = pSta->stats_info->retrans_count;

    // These COMMON params are not available for station from bwl
    sta_stats_bulk->errors_sent     = 0;
    sta_stats_bulk->errors_received = 0;

    // LOG(DEBUG) << "sta_mac=" << n->mac << ", signal_strength=" << int(n->stats_info->rx_rssi);
    sta_stats_bulk->uType.client.signal_strength = pSta->stats_info->rx_rssi;
    sta_stats_bulk->uType.client.last_data_downlink_rate =
        pSta->stats_info->tx_phy_rate_100kb * 100000;
    sta_stats_bulk->uType.client.last_data_uplink_rate =
        pSta->stats_info->rx_phy_rate_100kb * 100000;

    //These CLIENT SPECIFIC params are missing in DB:
    sta_stats_bulk->uType.client.retransmissions = 0;

    return stats_bulk_len;
}
