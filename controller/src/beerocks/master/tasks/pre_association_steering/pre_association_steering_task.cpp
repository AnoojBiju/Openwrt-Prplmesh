/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "pre_association_steering_task.h"
#include "../../db/db.h"
#include "../../son_actions.h"
#include "bml_pre_association_steering_defs.h"

#include <bcl/network/sockets.h>
#include <easylogging++.h>

#include <beerocks/tlvf/beerocks_message.h>
#include <beerocks/tlvf/beerocks_message_bml.h>
#include <tlvf/ieee_1905_1/tlvEndOfMessage.h>

#include <algorithm>
#include <climits>

using namespace beerocks;
using namespace son;

pre_association_steering_task::pre_association_steering_task(db &database_,
                                                             ieee1905_1::CmduMessageTx &cmdu_tx_,
                                                             task_pool &tasks_)
    : task("pre association steering task"), m_database(database_), m_cmdu_tx(cmdu_tx_),
      m_tasks(tasks_)
{
    int prev_task_id = m_database.get_pre_association_steering_task_id();
    if (prev_task_id != -1) {
        m_tasks.kill_task(prev_task_id);
    }
    database_.assign_pre_association_steering_task_id(this->id);
}

void pre_association_steering_task::work() { pending_request_events_check_timeout(); }

void pre_association_steering_task::handle_event(int event_type, void *obj)
{
    std::vector<int> events_updates_listeners;
    uint32_t idx = 0;
    int sd;

    while ((sd = get_bml_pre_association_steering_socket_at(idx)) !=
           beerocks::net::FileDescriptor::invalid_descriptor) {
        if (get_bml_pre_association_steering_events_update_enable(sd)) {
            events_updates_listeners.push_back(sd);
        }
        idx++;
    }

    eEvents _event_type = static_cast<eEvents>(event_type);

    switch (_event_type) {

    case STEERING_EVENT_REGISTER: {
        if (obj) {
            auto event_obj = static_cast<sListenerGeneralRegisterUnregisterEvent *>(obj);
            TASK_LOG(DEBUG) << "STEERING_EVENT_REGISTER event was received";
            add_bml_pre_association_steering_socket(event_obj->sd);
            if (!set_bml_pre_association_steering_events_update_enable(event_obj->sd, true)) {
                TASK_LOG(ERROR) << "fail in changing events_update registration";
                send_bml_response(_event_type, event_obj->sd, -BML_RET_REGISTERTION_FAIL);
                break;
            }
            send_bml_response(_event_type, event_obj->sd);
        }
        break;
    }
    case STEERING_EVENT_UNREGISTER: {
        if (obj) {
            auto event_obj = static_cast<sListenerGeneralRegisterUnregisterEvent *>(obj);
            TASK_LOG(DEBUG) << "UNREGISTER_TO_MONITOR_EVENT_UPDATES event was received";

            if (!set_bml_pre_association_steering_events_update_enable(event_obj->sd, false)) {
                TASK_LOG(DEBUG) << "fail in changing stats_update unregistration";
                send_bml_response(_event_type, event_obj->sd, -BML_RET_REGISTERTION_FAIL);
                break;
            }
            send_bml_response(_event_type, event_obj->sd);
        }
        break;
    }
    case STEERING_SET_GROUP_REQUEST: {
        if (obj) {
            auto event_obj =
                static_cast<pre_association_steering_task::sSteeringSetGroupRequestEvent *>(obj);
            TASK_LOG(INFO) << "STEERING_SET_GROUP_REQUEST event was received - remove - "
                           << int(event_obj->remove) << ", group_index "
                           << int(event_obj->steeringGroupIndex);

            if (!event_obj->remove) {
                if (!check_ap_cfgs_are_valid(event_obj->ap_cfgs)) {
                    send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd,
                                      -BML_RET_INVALID_ARGS);
                    break;
                }
            } else if (!event_obj->ap_cfgs.empty()) {
                TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST event: You shall not provide AP "
                                   "Configurations upon removing";
                send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd,
                                  -BML_RET_INVALID_ARGS);
                break;
            }

            std::vector<beerocks_message::sSteeringApConfig> cfgs;
            int32_t ret;
            if ((ret = steering_group_fill_ap_configuration(event_obj, cfgs)) < 0) {
                LOG(ERROR) << "STEERING_SET_GROUP_REQUEST Failed to fill ap configuration";
                send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd, ret);
                break;
            }
            //pre_association_steering_db.print_db();

            if (is_pending_request_event_exist(STEERING_SET_GROUP_REQUEST)) {
                TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST event is already initiated, but the "
                                   "response(s) are not received yet";
                send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd, -BML_RET_CMDU_FAIL);
            } else {
                add_pending_request_event(STEERING_SET_GROUP_REQUEST, event_obj->sd, cfgs.size());
            }
            //send new VS message to each slave with his specific data.
            for (const auto &cfg : cfgs) {
                auto update = message_com::create_vs_message<
                    beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST>(m_cmdu_tx);
                if (update == nullptr) {
                    TASK_LOG(ERROR) << "Failed building message!, removing "
                                       "STEERING_SET_GROUP_REQUEST from pending_events";
                    send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd,
                                      -BML_RET_CMDU_FAIL);
                    remove_pending_request_event(STEERING_SET_GROUP_REQUEST);
                    break;
                }
                update->params().remove             = event_obj->remove;
                update->params().steeringGroupIndex = event_obj->steeringGroupIndex;
                update->params().cfg                = cfg;
                auto vap_mac                        = tlvf::mac_to_string(cfg.bssid);
                auto radio_mac                      = m_database.get_node_parent_radio(vap_mac);
                if (radio_mac.empty()) {
                    TASK_LOG(ERROR) << "Database error: parent radio node of VAP MAC " << vap_mac
                                    << " is not found";
                    send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd,
                                      -BML_RET_CMDU_FAIL);
                    remove_pending_request_event(STEERING_SET_GROUP_REQUEST);
                    break;
                }
                auto agent_mac = m_database.get_node_parent_ire(radio_mac);
                if (tlvf::mac_to_string(agent_mac).empty()) {
                    TASK_LOG(ERROR) << "Database error: parent radio IRE node of radio MAC "
                                    << radio_mac << " is not found";
                    send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd,
                                      -BML_RET_CMDU_FAIL);
                    remove_pending_request_event(STEERING_SET_GROUP_REQUEST);
                    break;
                }
                m_sd = event_obj->sd;
                if (!son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac)) {
                    TASK_LOG(ERROR)
                        << "Failed send ACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST CMDU to "
                           "agent!, removing STEERING_SET_GROUP_REQUEST from pending_events";
                    send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd,
                                      -BML_RET_CMDU_FAIL);
                    remove_pending_request_event(STEERING_SET_GROUP_REQUEST);
                    break;
                }
                TASK_LOG(DEBUG)
                    << "Send  cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST to VAP = "
                    << vap_mac << " that belongs to radio " << radio_mac;
            }
        }
        break;
    }
    case STEERING_SET_GROUP_RESPONSE: {
        if (obj) {
            TASK_LOG(DEBUG) << "STEERING_SET_GROUP_RESPONSE event was received";
            if (!is_pending_request_event_exist(STEERING_SET_GROUP_REQUEST)) {
                TASK_LOG(ERROR) << "STEERING_SET_GROUP_RESPONSE event is invoked, but "
                                   "STEERING_SET_GROUP_REQUEST pending event does not exist";
                break;
            }
            int bml_sd = pending_request_event_get_bml_sd(STEERING_SET_GROUP_REQUEST);
            auto event_obj =
                static_cast<pre_association_steering_task::sSteeringSetGroupResponseEvent *>(obj);
            if (event_obj->ret_code < 0) {
                TASK_LOG(ERROR)
                    << "STEERING_SET_GROUP_RESPONSE event error received from the monitor";
                send_bml_response(_event_type, bml_sd, -BML_RET_OP_FAILED);
                break;
            }

            pending_request_event_increase_received_response(STEERING_SET_GROUP_REQUEST);
            if (is_pending_request_event_responses_match(STEERING_SET_GROUP_REQUEST)) {
                send_bml_response(_event_type, bml_sd);
                remove_pending_request_event(STEERING_SET_GROUP_REQUEST);
            }
        }
        break;
    }
    case STEERING_CLIENT_SET_REQUEST: {
        if (obj) {
            auto event_obj =
                static_cast<pre_association_steering_task::sSteeringClientSetRequestEvent *>(obj);
            auto client_mac = tlvf::mac_to_string(event_obj->client_mac);
            TASK_LOG(INFO) << "STEERING_CLIENT_SET_REQUEST event was received for client_mac "
                           << client_mac << " bssid " << event_obj->bssid;

            auto radio_mac = m_database.get_node_parent_radio(event_obj->bssid);
            if (radio_mac.empty()) {
                TASK_LOG(ERROR) << "Couldn't find radio with bssid " << event_obj->bssid;
                send_bml_response(STEERING_CLIENT_SET_RESPONSE, event_obj->sd, -BML_RET_OP_FAILED);
                break;
            }
            auto update = message_com::create_vs_message<
                beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_REQUEST>(m_cmdu_tx);
            if (update == nullptr) {
                TASK_LOG(ERROR) << "Failed building message!";
                send_bml_response(STEERING_CLIENT_SET_RESPONSE, event_obj->sd, -BML_RET_CMDU_FAIL);
                break;
            }
            // Check if configurations has changed and only then continue, else return OK
            auto configs_are_equal =
                [](const beerocks_message::sSteeringClientConfig &config1,
                   const beerocks_message::sSteeringClientConfig &config2) -> bool {
                return ((config1.snrProbeHWM == config2.snrProbeHWM) &&
                        (config1.snrProbeLWM == config2.snrProbeLWM) &&
                        (config1.snrAuthHWM == config2.snrAuthHWM) &&
                        (config1.snrAuthLWM == config2.snrAuthLWM) &&
                        (config1.snrInactXing == config2.snrInactXing) &&
                        (config1.snrHighXing == config2.snrHighXing) &&
                        (config1.snrLowXing == config2.snrLowXing) &&
                        (config1.authRejectReason == config2.authRejectReason));
            };

            // if trying to remove a non-existing client
            // or if the client configuration is the same as already configured,
            // no need to do anything - return success immediately
            std::shared_ptr<beerocks_message::sSteeringClientConfig> existing_config = nullptr;
            bool res = m_pre_association_steering_db.get_client_config(
                client_mac, event_obj->bssid, event_obj->steeringGroupIndex, existing_config);
            bool update_db_and_agent_is_needed = true;
            if (!res && event_obj->remove) {
                // client config doesn't exists in DB and and asked to be removed
                LOG(DEBUG) << "No need to remove from DB and update agent - client doesn't exist "
                              "in config";
                update_db_and_agent_is_needed = false;
            } else if (res && !event_obj->remove) {
                // client config exists in DB and asked to be added
                // Check if configuration has changed
                if (configs_are_equal(*existing_config, event_obj->config)) {
                    LOG(DEBUG) << "No need to update DB and agent - client configuration is same "
                                  "as existing configuration";
                    update_db_and_agent_is_needed = false;
                }
            }

            if (!update_db_and_agent_is_needed) {
                TASK_LOG(DEBUG) << "Sending STEERING_CLIENT_SET_RESPONSE event to BML";
                send_bml_response(STEERING_CLIENT_SET_RESPONSE, event_obj->sd);
                break;
            }

            // set or remove the client config
            res = event_obj->remove
                      ? m_pre_association_steering_db.clear_client_config(
                            client_mac, event_obj->bssid, event_obj->steeringGroupIndex)
                      : m_pre_association_steering_db.set_client_config(
                            client_mac, event_obj->bssid, event_obj->steeringGroupIndex,
                            event_obj->config);
            //pre_association_steering_db.print_db();
            if (!res) {
                TASK_LOG(ERROR) << "STEERING_CLIENT_SET_REQUEST db configuration failed";
                send_bml_response(STEERING_CLIENT_SET_RESPONSE, event_obj->sd, -BML_RET_CMDU_FAIL);
                break;
            }

            update->params().remove             = event_obj->remove;
            update->params().steeringGroupIndex = event_obj->steeringGroupIndex;
            update->params().bssid              = tlvf::mac_from_string(event_obj->bssid);
            update->params().client_mac         = event_obj->client_mac;
            update->params().config             = event_obj->config;

            /*
            add STEERING_CLIENT_SET_REQUEST twice because we expect
            responses from both Monitor and AP Manager.
            */
            add_pending_request_event(STEERING_CLIENT_SET_REQUEST, event_obj->sd, 2);

            LOG(DEBUG) << "Sending ACTION_CONTROL_STEERING_CLIENT_SET_REQUEST to radio "
                       << radio_mac;
            auto agent_mac = m_database.get_node_parent_ire(radio_mac);
            if (!son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac)) {
                send_bml_response(STEERING_CLIENT_SET_RESPONSE, event_obj->sd, -BML_RET_CMDU_FAIL);
                remove_pending_request_event(STEERING_CLIENT_SET_REQUEST);
                break;
            }
        }
        break;
    }
    case STEERING_CLIENT_SET_RESPONSE: {
        if (obj) {
            TASK_LOG(DEBUG) << "STEERING_CLIENT_SET_RESPONSE event was received";
            if (!is_pending_request_event_exist(STEERING_CLIENT_SET_REQUEST)) {
                TASK_LOG(ERROR) << "STEERING_CLIENT_SET_RESPONSE event is invoked, but "
                                   "STEERING_CLIENT_SET_REQUEST pending event does not exist";
                break;
            }
            int bml_sd = pending_request_event_get_bml_sd(STEERING_CLIENT_SET_REQUEST);
            auto event_obj =
                static_cast<pre_association_steering_task::sSteeringClientSetResponseEvent *>(obj);

            if (event_obj->ret_code < 0) {
                TASK_LOG(ERROR) << "STEERING_CLIENT_SET_RESPONSE event error received from the "
                                   "monitor/ap manager";
                if (!is_pending_request_event_exist(STEERING_SET_GROUP_REQUEST)) {
                    send_bml_response(_event_type, bml_sd, -BML_RET_OP_FAILED);
                }
                break;
            }

            pending_request_event_increase_received_response(STEERING_CLIENT_SET_REQUEST);
            if (is_pending_request_event_responses_match(STEERING_CLIENT_SET_REQUEST)) {
                send_bml_response(_event_type, bml_sd);
                remove_pending_request_event(STEERING_CLIENT_SET_REQUEST);
            }
        }
        break;
    }
    case STEERING_CLIENT_DISCONNECT_REQUEST: {
        if (obj) {
            auto event_obj         = static_cast<sSteeringClientDisconnectRequestEvent *>(obj);
            std::string client_mac = tlvf::mac_to_string(event_obj->client_mac);
            TASK_LOG(INFO) << "STEERING_CLIENT_DISCONNECT_REQUEST received for " << client_mac;
            add_pending_request_event(STEERING_CLIENT_DISCONNECT_REQUEST, event_obj->sd);
            son_actions::disconnect_client(m_database, m_cmdu_tx, client_mac, event_obj->bssid,
                                           event_obj->type, event_obj->reason,
                                           eClient_Disconnect_Source_Pre_Association_Steering_Task);
        }
        break;
    }
    case STEERING_CLIENT_DISCONNECT_RESPONSE: {
        if (obj) {
            TASK_LOG(DEBUG) << "STEERING_CLIENT_DISCONNECT_RESPONSE event was received";
            if (!is_pending_request_event_exist(STEERING_CLIENT_DISCONNECT_REQUEST)) {
                TASK_LOG(ERROR)
                    << "STEERING_CLIENT_DISCONNECT_RESPONSE event is invoked, but "
                       "STEERING_CLIENT_DISCONNECT_REQUEST pending event does not exist";
                break;
            }
            int bml_sd     = pending_request_event_get_bml_sd(STEERING_CLIENT_DISCONNECT_REQUEST);
            auto event_obj = static_cast<
                pre_association_steering_task::sSteeringClientDisconnectResponseEvent *>(obj);

            if (event_obj->ret_code < 0) {
                TASK_LOG(ERROR) << "STEERING_CLIENT_DISCONNECT_RESPONSE event error received";
                if (!is_pending_request_event_exist(STEERING_CLIENT_DISCONNECT_REQUEST)) {
                    send_bml_response(_event_type, bml_sd, -BML_RET_OP_FAILED);
                }
                break;
            }

            pending_request_event_increase_received_response(STEERING_CLIENT_DISCONNECT_REQUEST);
            if (is_pending_request_event_responses_match(STEERING_CLIENT_DISCONNECT_REQUEST)) {
                send_bml_response(_event_type, bml_sd);
                remove_pending_request_event(STEERING_CLIENT_DISCONNECT_REQUEST);
            }
        }
        break;
    }
    case STEERING_RSSI_MEASUREMENT_REQUEST: {
        if (obj) {
            auto event_obj = static_cast<sSteeringRssiMeasurementRequestEvent *>(obj);
            TASK_LOG(INFO) << "STEERING_RSSI_MEASUREMENT_REQUEST event was received for client_mac "
                           << event_obj->params.mac;

            auto update = message_com::create_vs_message<
                beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>(m_cmdu_tx,
                                                                                      id);
            if (update == nullptr) {
                TASK_LOG(ERROR) << "Failed building "
                                   "cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST message!";
                send_bml_response(STEERING_RSSI_MEASUREMENT_RESPONSE, event_obj->sd,
                                  -BML_RET_CMDU_FAIL);
                break;
            }

            update->params().channel                = event_obj->params.channel;
            update->params().cross                  = event_obj->params.cross;
            update->params().bandwidth              = event_obj->params.bandwidth;
            update->params().mon_ping_burst_pkt_num = event_obj->params.mon_ping_burst_pkt_num;
            update->params().vht_center_frequency   = event_obj->params.vht_center_frequency;
            update->params().measurement_delay      = event_obj->params.measurement_delay;
            std::copy_n(event_obj->params.mac.oct, sizeof(update->params().mac.oct),
                        update->params().mac.oct);
            std::copy_n(event_obj->params.ipv4.oct, sizeof(update->params().mac.oct),
                        update->params().ipv4.oct);

            auto radio_mac = m_database.get_node_parent_radio(event_obj->bssid);
            if (radio_mac.empty()) {
                TASK_LOG(ERROR) << "Couldn't find radio with bssid " << event_obj->bssid;
                send_bml_response(STEERING_RSSI_MEASUREMENT_RESPONSE, event_obj->sd,
                                  -BML_RET_CLIENT_NOT_FOUND);
                break;
            }

            // check that client exists in DB and connected to provided bssid
            std::string client_mac = tlvf::mac_to_string(event_obj->params.mac);
            auto bssid             = std::string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                send_bml_response(STEERING_RSSI_MEASUREMENT_RESPONSE, event_obj->sd,
                                  -BML_RET_CLIENT_NOT_CONFIGURED);
                break;
            }

            if (m_database.get_node_parent(client_mac) !=
                    event_obj->bssid || // client is not connected to provided bssid
                m_database.get_sta_state(client_mac) == beerocks::STATE_DISCONNECTED) {
                TASK_LOG(ERROR) << "Client " << client_mac << " is not connected to "
                                << event_obj->bssid;
                send_bml_response(STEERING_RSSI_MEASUREMENT_RESPONSE, event_obj->sd,
                                  -BML_RET_CLIENT_NOT_CONNECTED);
                break;
            }

            auto agent_mac = m_database.get_node_parent_ire(radio_mac);
            if (!son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac)) {
                send_bml_response(STEERING_SET_GROUP_RESPONSE, event_obj->sd, -BML_RET_CMDU_FAIL);
                break;
            }

            send_bml_response(STEERING_RSSI_MEASUREMENT_RESPONSE, event_obj->sd);
        }
        break;
    }
    case STEERING_RSSI_MEASUREMENT_RESPONSE: {
        if (obj) {
            TASK_LOG(DEBUG) << "STEERING_RSSI_MEASUREMENT_RESPONSE received";
        }
        break;
    }
    case STEERING_REMOVE_SOCKET: {
        if (obj) {
            auto event_obj = static_cast<sListenerGeneralRegisterUnregisterEvent *>(obj);
            if (is_bml_pre_association_steering_listener_socket(event_obj->sd)) {
                TASK_LOG(DEBUG) << "STEERING_REMOVE_SOCKET event was received";

                if (!set_bml_pre_association_steering_events_update_enable(event_obj->sd, false)) {
                    TASK_LOG(ERROR)
                        << "fail in set_bml_pre_association_steering_events_update_enable";
                }

                remove_bml_pre_association_steering_socket(event_obj->sd);
            }
        }
        break;
    }
    //events
    case STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION: {
        if (obj) {
            auto event_obj   = static_cast<beerocks_message::sSteeringEvActivity *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->client_mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION client_mac = "
                           << client_mac << " active=" << event_obj->active << " bssid = " << bssid
                           << " group index " << int(group_index);

            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG)
                    << "STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION no listener ignoring";
                break;
            }

            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto steering_event_client_activity_availble  = (BML_EVENT_STEERING *)event->data;
            steering_event_client_activity_availble->type = BML_STEERING_EVENT_CLIENT_ACTIVITY;

            steering_event_client_activity_availble->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN,
                        steering_event_client_activity_availble->bssid);
            steering_event_client_activity_availble->timestamp_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            std::copy_n(event_obj->client_mac.oct, BML_MAC_ADDR_LEN,
                        steering_event_client_activity_availble->data.activity.client_mac);
            steering_event_client_activity_availble->data.activity.active = event_obj->active;

            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }
    case STEERING_EVENT_SNR_XING_NOTIFICATION: {
        if (obj) {
            auto event_obj   = static_cast<beerocks_message::sSteeringEvSnrXing *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->client_mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_SNR_XING_NOTIFICATION client_mac = " << client_mac
                           << " bssid = " << bssid << " group index " << int(group_index);

            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG) << "STEERING_EVENT_SNR_XING_NOTIFICATION no listener ignoring";
                break;
            }

            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto steering_event_snr_xing_availble  = (BML_EVENT_STEERING *)event->data;
            steering_event_snr_xing_availble->type = BML_STEERING_EVENT_SNR_XING;

            steering_event_snr_xing_availble->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN,
                        steering_event_snr_xing_availble->bssid);
            steering_event_snr_xing_availble->timestamp_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            std::copy_n(event_obj->client_mac.oct, BML_MAC_ADDR_LEN,
                        steering_event_snr_xing_availble->data.snrXing.client_mac);
            steering_event_snr_xing_availble->data.snrXing.snr = event_obj->snr;
            steering_event_snr_xing_availble->data.snrXing.inactveXing =
                BML_STEERING_SNR_CHANGE(event_obj->inactveXing);
            steering_event_snr_xing_availble->data.snrXing.highXing =
                BML_STEERING_SNR_CHANGE(event_obj->highXing);
            steering_event_snr_xing_availble->data.snrXing.lowXing =
                BML_STEERING_SNR_CHANGE(event_obj->lowXing);
            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }
    case STEERING_EVENT_RSSI_MEASUREMENT_SNR_NOTIFICATION: {
        if (obj) {
            auto event_obj   = static_cast<beerocks_message::sSteeringEvSnr *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->client_mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_RSSI_MEASUREMENT_SNR_NOTIFICATION client_mac = "
                           << client_mac << " bssid = " << bssid << " group index "
                           << int(group_index);

            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG)
                    << "STEERING_EVENT_RSSI_MEASUREMENT_SNR_NOTIFICATION no listener ignoring";
                break;
            }

            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto steering_event_snr_availble  = (BML_EVENT_STEERING *)event->data;
            steering_event_snr_availble->type = BML_STEERING_EVENT_RSSI_MEASUREMENT;

            steering_event_snr_availble->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN, steering_event_snr_availble->bssid);
            steering_event_snr_availble->timestamp_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            std::copy_n(event_obj->client_mac.oct, BML_MAC_ADDR_LEN,
                        steering_event_snr_availble->data.clientMeasurement.client_mac);
            steering_event_snr_availble->data.clientMeasurement.snr = event_obj->snr;
            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }
    case STEERING_EVENT_PROBE_REQ_NOTIFICATION: {
        if (obj) {
            auto event_obj   = static_cast<beerocks_message::sSteeringEvProbeReq *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->client_mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_PROBE_REQ_NOTIFICATION client_mac = " << client_mac
                           << " bssid = " << bssid << " group index " << int(group_index);

            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG) << "STEERING_EVENT_PROBE_REQ_NOTIFICATION no listener ignoring";
                break;
            }

            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto steering_event_probe_req_availble  = (BML_EVENT_STEERING *)event->data;
            steering_event_probe_req_availble->type = BML_STEERING_EVENT_PROBE_REQ;

            steering_event_probe_req_availble->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN,
                        steering_event_probe_req_availble->bssid);
            steering_event_probe_req_availble->timestamp_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            std::copy_n(event_obj->client_mac.oct, BML_MAC_ADDR_LEN,
                        steering_event_probe_req_availble->data.probeReq.client_mac);
            steering_event_probe_req_availble->data.probeReq.snr       = event_obj->rx_snr;
            steering_event_probe_req_availble->data.probeReq.broadcast = event_obj->broadcast;
            steering_event_probe_req_availble->data.probeReq.blocked   = event_obj->blocked;
            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }
    case STEERING_EVENT_AUTH_FAIL_NOTIFICATION: {
        if (obj) {
            auto event_obj   = static_cast<beerocks_message::sSteeringEvAuthFail *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->client_mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_AUTH_FAIL_NOTIFICATION client_mac = " << client_mac
                           << " bssid = " << bssid << " group index " << int(group_index);

            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG) << "STEERING_EVENT_AUTH_FAIL_NOTIFICATION no listener ignoring";
                break;
            }

            if (group_index == -1) {
                TASK_LOG(DEBUG) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto steering_event_auth_fail_availble  = (BML_EVENT_STEERING *)event->data;
            steering_event_auth_fail_availble->type = BML_STEERING_EVENT_AUTH_FAIL;

            steering_event_auth_fail_availble->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN,
                        steering_event_auth_fail_availble->bssid);
            steering_event_auth_fail_availble->timestamp_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            std::copy_n(event_obj->client_mac.oct, BML_MAC_ADDR_LEN,
                        steering_event_auth_fail_availble->data.authFail.client_mac);
            steering_event_auth_fail_availble->data.authFail.snr        = event_obj->rx_snr;
            steering_event_auth_fail_availble->data.authFail.reason     = event_obj->reason;
            steering_event_auth_fail_availble->data.authFail.bsBlocked  = event_obj->blocked;
            steering_event_auth_fail_availble->data.authFail.bsRejected = event_obj->reject;
            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }
    case STEERING_EVENT_CLIENT_CONNECT_NOTIFICATION: {
        if (obj) {
            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG) << "receive STEERING_EVENT_CLIENT_CONNECT_NOTIFICATION, no "
                                   "listeners. ignoring";
                break;
            }
            auto event_obj   = static_cast<bwl::sClientAssociationParams *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_CLIENT_CONNECT_NOTIFICATION client_mac = "
                           << client_mac << " bssid = " << bssid << " group index "
                           << int(group_index);

            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto wifi_channel = m_database.get_radio_wifi_channel(
                tlvf::mac_from_string(m_database.get_node_parent_radio(client_mac)));
            if (wifi_channel.is_empty()) {
                TASK_LOG(ERROR) << "wifiChannel of " << m_database.get_node_parent_radio(client_mac)
                                << " is empty";
                break;
            }
            auto freq_type   = wifi_channel.get_freq_type();
            auto client_caps = m_database.get_sta_capabilities(client_mac, freq_type);

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto connect_event                = (BML_EVENT_STEERING *)event->data;
            connect_event->type               = BML_STEERING_EVENT_CLIENT_CONNECT;
            connect_event->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN, connect_event->bssid);
            connect_event->timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count();

            std::copy_n(tlvf::mac_from_string(client_mac).oct, BML_MAC_ADDR_LEN,
                        connect_event->data.connect.client_mac);
            connect_event->data.connect.isBTMSupported = client_caps->btm_supported;
            connect_event->data.connect.isRRMSupported = client_caps->rrm_supported;
            connect_event->data.connect.bandCap2G      = client_caps->band_2g_capable;
            connect_event->data.connect.bandCap5G      = client_caps->band_5g_capable;
            connect_event->data.connect.bandCap6G      = client_caps->band_6g_capable;

            connect_event->data.connect.datarateInfo.maxChwidth = client_caps->max_ch_width;
            connect_event->data.connect.datarateInfo.maxStreams = client_caps->max_streams;
            connect_event->data.connect.datarateInfo.phyMode    = client_caps->phy_mode;
            connect_event->data.connect.datarateInfo.maxMCS     = client_caps->max_mcs;
            connect_event->data.connect.datarateInfo.maxTxpower = client_caps->max_tx_power;
            connect_event->data.connect.datarateInfo.isStaticSmps =
                (client_caps->ht_sm_power_save == HT_SM_POWER_SAVE_MODE_STATIC);
            connect_event->data.connect.datarateInfo.isMUMimoSupported =
                client_caps->mumimo_supported;

            connect_event->data.connect.rmCaps.linkMeas      = client_caps->link_meas;
            connect_event->data.connect.rmCaps.neighRpt      = client_caps->nr_enabled;
            connect_event->data.connect.rmCaps.bcnRptPassive = client_caps->beacon_report_passive;
            connect_event->data.connect.rmCaps.bcnRptActive  = client_caps->beacon_report_active;
            connect_event->data.connect.rmCaps.bcnRptTable   = client_caps->beacon_report_table;
            connect_event->data.connect.rmCaps.lciMeas       = client_caps->lci_meas;
            connect_event->data.connect.rmCaps.ftmRangeRpt   = client_caps->fmt_range_report;
            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }
    case STEERING_EVENT_CLIENT_DISCONNECT_NOTIFICATION: {
        if (obj) {
            if (events_updates_listeners.empty()) {
                TASK_LOG(DEBUG) << "receive STEERING_EVENT_CLIENT_DISCONNECT_NOTIFICATION, no "
                                   "listeners. ignoring";
                break;
            }
            auto event_obj   = static_cast<beerocks_message::sSteeringEvDisconnect *>(obj);
            auto client_mac  = tlvf::mac_to_string(event_obj->client_mac);
            auto bssid       = tlvf::mac_to_string(event_obj->bssid);
            auto group_index = m_pre_association_steering_db.get_group_index(client_mac, bssid);
            TASK_LOG(INFO) << "STEERING_EVENT_CLIENT_DISCONNECT_NOTIFICATION client_mac = "
                           << client_mac << " bssid = " << bssid << " group index "
                           << int(group_index) << " reason " << int(event_obj->reason) << " source "
                           << int(event_obj->source) << " type " << int(event_obj->type);

            if (group_index == -1) {
                TASK_LOG(ERROR) << "event for un-configured client mac - " << client_mac
                                << " ignored";
                break;
            }

            auto response = message_com::create_vs_message<
                beerocks_message::cACTION_BML_STEERING_EVENTS_UPDATE>(m_cmdu_tx);
            if (response == nullptr) {
                TASK_LOG(ERROR) << "Failed building cACTION_BML_STEERING_EVENTS_UPDATE message!";
                return;
            }

            if (!response->alloc_buffer(sizeof(BML_EVENT) + sizeof(BML_EVENT_STEERING))) {
                TASK_LOG(ERROR) << "Failed to alloc buffer";
                return;
            }

            auto event  = (BML_EVENT *)response->buffer(0);
            event->type = BML_EVENT_TYPE_STEERING;
            event->data = response->buffer(sizeof(BML_EVENT));

            auto steering_event_client_disconnect_availble  = (BML_EVENT_STEERING *)event->data;
            steering_event_client_disconnect_availble->type = BML_STEERING_EVENT_CLIENT_DISCONNECT;
            steering_event_client_disconnect_availble->steeringGroupIndex = group_index;
            std::copy_n(event_obj->bssid.oct, BML_MAC_ADDR_LEN,
                        steering_event_client_disconnect_availble->bssid);
            steering_event_client_disconnect_availble->timestamp_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();

            std::copy_n(event_obj->client_mac.oct, BML_MAC_ADDR_LEN,
                        steering_event_client_disconnect_availble->data.disconnect.client_mac);
            steering_event_client_disconnect_availble->data.disconnect.reason = event_obj->reason;
            steering_event_client_disconnect_availble->data.disconnect.source =
                BML_DISCONNECT_SOURCE(event_obj->source);
            steering_event_client_disconnect_availble->data.disconnect.type =
                BML_DISCONNECT_TYPE(event_obj->type);
            send_bml_event_to_listeners(m_cmdu_tx, events_updates_listeners);
        }
        break;
    }

    case STEERING_SLAVE_JOIN: {
        if (!obj) {
            LOG(ERROR) << "STEERING_SLAVE_JOIN without data!";
            break;
        }

        TASK_LOG(INFO) << "STEERING_SLAVE_JOIN event was received";
        auto event_obj = static_cast<sSteeringSlaveJoinEvent *>(obj);
        if (m_pre_association_steering_db.get_steering_group_list().empty()) {
            TASK_LOG(INFO) << "no configuration to re-send to agent, radio_mac -"
                           << event_obj->radio_mac;
            break;
        }
        send_steering_conf_to_agent(event_obj->radio_mac);
        break;
    }

    default: {
        TASK_LOG(ERROR) << "UNKNOWN event was received";
        break;
    }
    }
}

bool pre_association_steering_task::is_bml_pre_association_steering_listener_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = m_bml_pre_association_steering_listeners_sockets.begin();
             it < m_bml_pre_association_steering_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return true;
            }
        }
    }
    return false;
}

int pre_association_steering_task::get_bml_pre_association_steering_socket_at(uint32_t idx)
{
    if (idx < (m_bml_pre_association_steering_listeners_sockets.size())) {
        return m_bml_pre_association_steering_listeners_sockets.at(idx).sd;
    }
    return beerocks::net::FileDescriptor::invalid_descriptor;
}

bool pre_association_steering_task::get_bml_pre_association_steering_events_update_enable(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = m_bml_pre_association_steering_listeners_sockets.begin();
             it < m_bml_pre_association_steering_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return (*it).events_updates;
            }
        }
    }
    return false;
}

bool pre_association_steering_task::set_bml_pre_association_steering_events_update_enable(
    int sd, bool update_enable)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = m_bml_pre_association_steering_listeners_sockets.begin();
             it < m_bml_pre_association_steering_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                (*it).events_updates = update_enable;
                return true;
            }
        }
    }
    return false;
}

void pre_association_steering_task::add_bml_pre_association_steering_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = m_bml_pre_association_steering_listeners_sockets.begin();
             it < m_bml_pre_association_steering_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return;
            }
        }
        sBmlPreAssociationSteeringListener bml_pre_association_steering_listener = {0};
        bml_pre_association_steering_listener.sd                                 = sd;
        m_bml_pre_association_steering_listeners_sockets.push_back(
            bml_pre_association_steering_listener);
    }
}

void pre_association_steering_task::remove_bml_pre_association_steering_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = m_bml_pre_association_steering_listeners_sockets.begin();
             it < m_bml_pre_association_steering_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                it = m_bml_pre_association_steering_listeners_sockets.erase(it);
                return;
            }
        }
    }
}

void pre_association_steering_task::send_bml_event_to_listeners(
    ieee1905_1::CmduMessageTx &cmdu_tx, const std::vector<int> &bml_listeners)
{
    auto controller_ctx = m_database.get_controller_ctx();
    if (!controller_ctx) {
        LOG(ERROR) << "controller_ctx == nullptr";
        return;
    }

    for (int fd : bml_listeners) {
        controller_ctx->send_cmdu(fd, cmdu_tx);
    }
}

bool pre_association_steering_task::send_steering_conf_to_agent(const std::string &radio_mac)
{
    auto agent_mac = m_database.get_node_parent_ire(radio_mac);
    size_t idx     = 0;

    for (const auto &steering_group : m_pre_association_steering_db.get_steering_group_list()) {
        auto update = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST>(m_cmdu_tx);
        if (update == nullptr) {
            TASK_LOG(ERROR) << "Failed building message!";
            return false;
        }

        update->params().steeringGroupIndex = steering_group.first;
        auto &client_list = steering_group.second->get_ap_configs()[idx].get_client_config_list();
        update->params().cfg = steering_group.second->get_ap_configs()[idx].get_ap_config();
        auto bssid           = steering_group.second->get_ap_configs()[idx].get_bssid();
        idx++;
        TASK_LOG(DEBUG) << "send cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST to agent "
                        << agent_mac << " radio_mac " << radio_mac;
        son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac);
        //sending client configuration for specifc group
        for (auto client_entry : client_list) {
            auto steer_client_update = message_com::create_vs_message<
                beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_REQUEST>(m_cmdu_tx);
            if (steer_client_update == nullptr) {
                TASK_LOG(ERROR) << "Failed building message!";
                return false;
            }

            steer_client_update->params().steeringGroupIndex = steering_group.first;
            steer_client_update->params().bssid              = tlvf::mac_from_string(bssid);
            steer_client_update->params().client_mac = tlvf::mac_from_string(client_entry.first);
            steer_client_update->params().config     = *(client_entry.second->get_client_config());
            TASK_LOG(DEBUG) << "send cACTION_CONTROL_STEERING_CLIENT_SET to agent " << agent_mac
                            << " radio_mac " << radio_mac;
            son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac);
        }
    }
    return true;
}

int32_t pre_association_steering_task::steering_group_fill_ap_configuration(
    sSteeringSetGroupRequestEvent *event_obj,
    std::vector<beerocks_message::sSteeringApConfig> &ap_cfgs_)
{
    if (!event_obj->remove) {
        for (auto &ap_cfg : event_obj->ap_cfgs) {
            if (ap_cfg.inactCheckIntervalSec > ap_cfg.inactCheckThresholdSec ||
                ap_cfg.inactCheckIntervalSec > ap_cfg.inactCheckThresholdSec) {
                TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST inactCheckIntervalSec >= "
                                   "inactCheckThresholdSec , invalid configuration";
                return -BML_RET_INVALID_CONFIGURATION;
            }
        }
        m_pre_association_steering_db.set_steering_group_config(event_obj->steeringGroupIndex,
                                                                event_obj->ap_cfgs);
    } else {
        auto steering_group_list = m_pre_association_steering_db.get_steering_group_list();
        if (steering_group_list.find(event_obj->steeringGroupIndex) == steering_group_list.end()) {
            TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST nothing to remove for groupindex = "
                            << int(event_obj->steeringGroupIndex);
            return -BML_RET_INVALID_CONFIGURATION;
        }
    }

    auto steering_group_config = m_pre_association_steering_db.get_steering_group_list()
                                     .find(event_obj->steeringGroupIndex)
                                     ->second;

    for (auto ap_cfg : steering_group_config->get_ap_configs()) {
        ap_cfgs_.push_back(ap_cfg.get_ap_config());
    }

    if (event_obj->remove) {
        if (!m_pre_association_steering_db.clear_steering_group_config(
                event_obj->steeringGroupIndex)) {
            LOG(ERROR) << "STEERING_SET_GROUP_REQUEST db configuration failed";
            return -BML_RET_INVALID_CONFIGURATION;
        }
    }
    return BML_RET_OK;
}

void pre_association_steering_task::send_bml_response(eEvents event, int sd, int32_t ret)
{
    auto controller_ctx = m_database.get_controller_ctx();
    if (!controller_ctx) {
        LOG(ERROR) << "controller_ctx == nullptr";
        return;
    }

    switch (event) {
    case STEERING_EVENT_UNREGISTER:
    case STEERING_EVENT_REGISTER: {
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_BML_STEERING_EVENT_REGISTER_UNREGISTER_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR) << "Failed building ACTION_BML_STEERING_EVENT_REGISTER_UNREGISTER_RESPONSE "
                          "message!";
            break;
        }

        response->error_code() = ret;

        //send response to bml
        controller_ctx->send_cmdu(sd, m_cmdu_tx);
        break;
    }
    case STEERING_SET_GROUP_RESPONSE: {
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_BML_STEERING_SET_GROUP_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR) << "Failed building ACTION_BML_STEERING_SET_GROUP_RESPONSE message!";
            break;
        }
        LOG(DEBUG) << "sent ACTION_BML_STEERING_SET_GROUP_RESPONSE message, ret=" << int(ret);
        response->error_code() = ret;

        //send response to bml
        controller_ctx->send_cmdu(sd, m_cmdu_tx);
        break;
    }
    case STEERING_CLIENT_SET_RESPONSE: {
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_BML_STEERING_CLIENT_SET_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR) << "Failed building ACTION_BML_STEERING_CLIENT_SET_RESPONSE message!";
            break;
        }
        LOG(DEBUG) << "sent ACTION_BML_STEERING_CLIENT_SET_RESPONSE message, ret=" << int(ret);
        response->error_code() = ret;

        //send response to bml
        controller_ctx->send_cmdu(sd, m_cmdu_tx);
        break;
    }
    case STEERING_CLIENT_DISCONNECT_RESPONSE: {
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_BML_STEERING_CLIENT_DISCONNECT_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR)
                << "Failed building cACTION_BML_STEERING_CLIENT_DISCONNECT_RESPONSE message!";
            break;
        }

        response->error_code() = ret;

        //send response to bml
        controller_ctx->send_cmdu(sd, m_cmdu_tx);
        break;
    }
    case STEERING_RSSI_MEASUREMENT_RESPONSE: {
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_BML_STEERING_CLIENT_MEASURE_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR) << "Failed building ACTION_BML_STEERING_CLIENT_MEASURE_RESPONSE message!";
            break;
        }

        response->error_code() = ret;

        //send response to bml
        controller_ctx->send_cmdu(sd, m_cmdu_tx);
        break;
    }
    default: {
        TASK_LOG(ERROR) << "UNKNOWN event was received, event = " << int(event);
        break;
    }
    }
    return;
}
void pre_association_steering_task::add_pending_request_event(eEvents event, int bml_sd,
                                                              uint32_t num_of_expected_responses)
{
    sPendingEvent pending_event{};
    pending_event.bml_sd                    = bml_sd;
    pending_event.current_time              = std::chrono::steady_clock::now();
    pending_event.num_of_expected_responses = num_of_expected_responses;
    pending_event.num_of_received_responses = 0;

    m_pending_request_events.insert(std::make_pair(event, pending_event));
}

void pre_association_steering_task::pending_request_event_increase_received_response(eEvents event)
{
    m_pending_request_events[event].num_of_received_responses++;
}

void pre_association_steering_task::remove_pending_request_event(eEvents event)
{
    m_pending_request_events.erase(event);
}
bool pre_association_steering_task::is_pending_request_event_exist(eEvents event)
{
    return m_pending_request_events.find(event) != m_pending_request_events.end();
}
bool pre_association_steering_task::is_pending_request_event_responses_match(eEvents event)
{
    return m_pending_request_events[event].num_of_expected_responses ==
           m_pending_request_events[event].num_of_received_responses;
}

int pre_association_steering_task::pending_request_event_get_bml_sd(eEvents event)
{
    return m_pending_request_events[event].bml_sd;
}

void pre_association_steering_task::pending_request_events_check_timeout()
{
    for (auto it = m_pending_request_events.begin(); it != m_pending_request_events.end();) {
        if (std::chrono::steady_clock::now() >
            it->second.current_time + std::chrono::seconds(event_timeout)) {
            m_pending_request_events.erase(it);
        } else {
            ++it;
        }
    }
}

bool pre_association_steering_task::check_ap_cfgs_are_valid(
    std::vector<beerocks_message::sSteeringApConfig> &ap_cfgs)
{
    std::string vap_bssid, radio_mac;
    std::unordered_map<std::string, size_t> vap_bssids_map;
    std::unordered_map<std::string, size_t>::iterator bssid_it;
    if (ap_cfgs.empty()) {
        TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST event: There are no AP Configurations";
        return false;
    }
    for (size_t i = 0; i < ap_cfgs.size(); ++i) {
        vap_bssid = tlvf::mac_to_string(ap_cfgs[i].bssid);
        radio_mac = m_database.get_node_parent_radio(vap_bssid);
        if (radio_mac.empty()) {
            TASK_LOG(ERROR)
                << "STEERING_SET_GROUP_REQUEST event: radio_mac that was retrieved from VAP "
                << vap_bssid << " is empty";
            return false;
        }
        sMacAddr radio_mac_addr = tlvf::mac_from_string(radio_mac);
        if (!(m_database.is_radio_24ghz(radio_mac_addr) ||
              m_database.is_radio_5ghz(radio_mac_addr) ||
              m_database.is_radio_6ghz(radio_mac_addr))) {
            TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST event: radio mac " << radio_mac
                            << " is not 2.4GHz, 5GHz, or 6GHz";
            return false;
        }

        bssid_it = vap_bssids_map.find(vap_bssid);
        if (bssid_it == vap_bssids_map.end()) {
            vap_bssids_map.emplace(vap_bssid, i + 1);
        } else {
            TASK_LOG(ERROR) << "STEERING_SET_GROUP_REQUEST event: The BSSID " << bssid_it->first
                            << " of AP Configurations " << bssid_it->second << " and " << i + 1
                            << " are the same";
            return false;
        }
    }

    return true;
}
