/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "client_locating_task.h"
#include "../db/db_algo.h"
#include "../son_actions.h"
#include "bml_task.h"

#include <easylogging++.h>

using namespace beerocks;
using namespace net;
using namespace son;

client_locating_task::client_locating_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                           task_pool &tasks_, const std::string &client_mac_,
                                           bool new_connection_, int starting_delay_ms_,
                                           const std::string &eth_switch_,
                                           const std::string &task_name_)
    : task(task_name_), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_),
      client_mac(client_mac_), new_connection(new_connection_),
      starting_delay_ms(starting_delay_ms_), eth_switch(eth_switch_)
{
}

void client_locating_task::work()
{
    auto client = database.get_station(tlvf::mac_from_string(client_mac));
    if (!client) {
        TASK_LOG(ERROR) << "client " << client_mac << " not found";
        finish();
        return;
    }

    std::shared_ptr<Agent> agent = database.get_agent(tlvf::mac_from_string(client_mac));
    if (agent && !agent->is_gateway) {
        std::shared_ptr<Station> bh_sta = database.get_station(agent->parent_mac);
        if (!bh_sta) {
            finish();
            return;
        }
        if (bh_sta->get_bss()) {
            TASK_LOG(DEBUG) << "Agent is wireless -> finish task";
            finish();
        }
    } else if (client->get_bss()) {
        TASK_LOG(DEBUG) << "client is wireless -> finish task";
        finish();
    }
    switch (state) {
    case START: {
        if ((!new_connection) && (eth_switch == network_utils::ZERO_MAC_STRING)) {
            TASK_LOG(DEBUG) << "bad task input args -> finish task";
            finish();
        } else if ((!new_connection) &&
                   (database.get_sta_state(client_mac) == beerocks::STATE_DISCONNECTED)) {
            TASK_LOG(DEBUG)
                << "task in disconnect mode when client is already disconnected -> finish task";
            finish();
        } else if (client->is_bSta()) {
            TASK_LOG(DEBUG) << "not handeling bSta type -> finish task";
            finish();
        } else {
            int prev_task_id = client->get_client_locating_task_id(new_connection);
            tasks.kill_task(prev_task_id);
            client->assign_client_locating_task_id(id, new_connection);
            TASK_LOG(DEBUG) << "new task initiate with new_connection "
                            << std::string(new_connection ? "on" : "off");

            client_ipv4 = database.get_sta_ipv4(client_mac);

            state = SEND_ARP_QUERIES;
            wait_for(starting_delay_ms);
        }
    } break;

    case SEND_ARP_QUERIES: {
        auto agents      = database.get_all_connected_agents();
        pending_ires_num = 0;

        for (auto &agent_it : agents) {
            auto ire = tlvf::mac_to_string(agent_it->al_mac);

            auto request =
                message_com::create_vs_message<beerocks_message::cACTION_CONTROL_ARP_QUERY_REQUEST>(
                    cmdu_tx, id);
            if (request == nullptr) {
                LOG(ERROR) << "Failed building message!";
                continue;
            }
            request->params().mac  = tlvf::mac_from_string(client_mac);
            request->params().ipv4 = network_utils::ipv4_from_string(client_ipv4);

            if ((ire == client_mac) || (client_mac == tlvf::mac_to_string(agent_it->parent_mac))) {
                continue;
            }

            if (!agent_it->backhaul.wireless_backhaul_radio) {
                TASK_LOG(WARNING) << "backhaul manager radio is not set!";
                continue;
            }

            auto backhaul_manager_hostap =
                tlvf::mac_to_string(agent_it->backhaul.wireless_backhaul_radio->radio_uid);

            auto agent_mac = database.get_radio_parent_agent(
                agent_it->backhaul.wireless_backhaul_radio->radio_uid);

            son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database, backhaul_manager_hostap);

            add_pending_mac(backhaul_manager_hostap,
                            beerocks_message::ACTION_CONTROL_ARP_QUERY_RESPONSE);
            pending_ires_num++;

            TASK_LOG(DEBUG) << "requesting arp query from hostap_backhaul " << ire
                            << " (backhaul_manager_hostap=" << backhaul_manager_hostap
                            << ") for client_mac=" << client_mac << " ipv4=" << client_ipv4;
        }
        TASK_LOG(DEBUG) << "waiting for arp respones";
        set_responses_timeout(task_timeout_seconds * 1000);
        state = FINISH;
    } break;

    case FINISH: {
        /*
             * right now this task only handles ETH clients
             */
        if (new_connection) {
            if (!deepest_slave.empty() &&
                pending_ires_num == 0) { // set hierarchy if received answer from all ires
                TASK_LOG(DEBUG) << "deepest slave is: " << deepest_slave
                                << " hierarchy=" << deepest_slave_hierarchy << " placing client "
                                << client_mac << " under it";
                std::shared_ptr<Agent> deepest_slave_agent =
                    database.get_agent(tlvf::mac_from_string(deepest_slave));
                if (!deepest_slave_agent || deepest_slave_agent->eth_switches.empty()) {
                    TASK_LOG(ERROR) << "no eth_switch for slave " << deepest_slave;
                } else {
                    auto client_parent  = database.get_sta_parent(client_mac);
                    auto client_state   = database.get_sta_state(client_mac);
                    sMacAddr eth_sw_mac = deepest_slave_agent->eth_switches.begin()->first;

                    TASK_LOG(DEBUG)
                        << "client_mac = " << client_mac << " (" << int(client_state) << ")"
                        << ", client_parent = " << client_parent << ", eth_sw_mac = " << eth_sw_mac;

                    // update database and bml listeners if client moved or newly connected
                    if ((client_parent != tlvf::mac_to_string(eth_sw_mac)) ||
                        (client_state != beerocks::STATE_CONNECTED)) {
                        // update node
                        if (agent && !agent->is_gateway) {
                            database.add_backhaul_station(agent->parent_mac, eth_sw_mac);
                        } else {
                            database.add_station(network_utils::ZERO_MAC,
                                                 tlvf::mac_from_string(client_mac), eth_sw_mac);
                            database.set_sta_state(client_mac, beerocks::STATE_CONNECTED);
                        }

                        // update bml listeners
                        bml_task::connection_change_event new_event;
                        new_event.mac = client_mac;
                        tasks.push_event(database.get_bml_task_id(), bml_task::CONNECTION_CHANGE,
                                         &new_event);
                        TASK_LOG(DEBUG)
                            << "BML, sending client eth connect CONNECTION_CHANGE for mac "
                            << new_event.mac;
                    }
                }
            } else {
                TASK_LOG(DEBUG) << "couldn't find deepest slave";
            }
        } else {
            TASK_LOG(DEBUG) << "ETH client disconnected! " << client_mac
                            << " from eth_switch=" << eth_switch;
            // non of the pending ires replied about that client
            if (agent) {
                auto backhaul_mac = database.get_agent_parent(tlvf::mac_from_string(client_mac));
                bool reported_by_parent =
                    eth_switch == database.get_sta_parent(tlvf::mac_to_string(backhaul_mac));
                son_actions::handle_dead_station(tlvf::mac_to_string(backhaul_mac),
                                                 reported_by_parent, database, tasks);
            } else {
                std::shared_ptr<Station> station =
                    database.get_station(tlvf::mac_from_string(client_mac));
                if (station) {
                    bool reported_by_parent = eth_switch == database.get_sta_parent(client_mac);
                    son_actions::handle_dead_station(client_mac, reported_by_parent, database,
                                                     tasks);
                }
            }
        }
        finish();
    } break;
    }
}

void client_locating_task::handle_response(std::string mac,
                                           std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_CONTROL_ARP_QUERY_RESPONSE: {
        auto response =
            beerocks_header->getClass<beerocks_message::cACTION_CONTROL_ARP_QUERY_RESPONSE>();
        if (!response) {
            TASK_LOG(ERROR) << "getClass failed for cACTION_CONTROL_ARP_QUERY_RESPONSE";
            return;
        }

        pending_ires_num--;

        std::string ipv4    = network_utils::ipv4_to_string(response->params().ipv4);
        std::string arp_mac = tlvf::mac_to_string(response->params().mac);

        TASK_LOG(DEBUG) << "received response from slave " << mac << ":" << std::endl
                        << "   arp_mac=" << arp_mac << std::endl
                        << "   arp_ipv4=" << ipv4 << std::endl
                        << "   arp_state=" << int(response->params().state)
                        << " arp_source=" << int(response->params().source);

        if (new_connection) {
            if (client_ipv4 == ipv4 &&
                /*(response->params.state == beerocks::ARP_NUD_REACHABLE || response->params.state == beerocks::ARP_NUD_STALE) &&*/
                (response->params().source == beerocks::ARP_SRC_ETH_FRONT ||
                 response->params().source == beerocks::ARP_SRC_WIRELESS_FRONT)) {
                TASK_LOG(DEBUG) << "slave mac " << mac << " has client_mac " << client_mac
                                << " ipv4=" << client_ipv4 << " on front iface";
                int hierarchy = database.get_agent_hierarchy(tlvf::mac_from_string(mac));
                if (hierarchy > deepest_slave_hierarchy) {
                    deepest_slave_hierarchy = hierarchy;
                    deepest_slave           = mac;
                    TASK_LOG(DEBUG) << "deepest slave so far: " << deepest_slave
                                    << " hierarchy=" << deepest_slave_hierarchy;
                }
            }
            if (!pending_ires_num) {
                work(); // go to FINISH STATE
            }
        } else {
            TASK_LOG(DEBUG) << "finish task";
            finish();
        }
        break;
    }
    default: {
        TASK_LOG(ERROR) << "Unsupported action_op:" << int(beerocks_header->action_op());
        break;
    }
    }
}

bool client_locating_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                                 ieee1905_1::CmduMessageRx &cmdu_rx)
{
    return false;
}
