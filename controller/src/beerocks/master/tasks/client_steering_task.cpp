/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "client_steering_task.h"
#include "../db/db_algo.h"
#include "../son_actions.h"
#include "bml_task.h"

#include <bcl/network/network_utils.h>
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <easylogging++.h>
#include <tlvf/wfa_map/tlvBackhaulSteeringRequest.h>
#include <tlvf/wfa_map/tlvClientAssociationControlRequest.h>
#include <tlvf/wfa_map/tlvSteeringRequest.h>

using namespace beerocks;
using namespace net;
using namespace son;

client_steering_task::client_steering_task(db &database, ieee1905_1::CmduMessageTx &cmdu_tx,
                                           task_pool &tasks, const std::string &sta_mac,
                                           const std::string &target_bssid,
                                           const std::string &triggered_by,
                                           const std::string &steering_type, bool disassoc_imminent,
                                           int disassoc_timer_ms, bool steer_restricted,
                                           const std::string &task_name)
    : task(task_name), m_database(database), m_cmdu_tx(cmdu_tx), m_tasks(tasks), m_sta_mac(sta_mac),
      m_target_bssid(target_bssid), //Chosen VAP BSSID to steer the client to
      m_triggered_by(triggered_by), m_steering_type(steering_type),
      m_disassoc_imminent(disassoc_imminent), m_disassoc_timer_ms(disassoc_timer_ms),
      m_steer_restricted(steer_restricted)
{
}

void client_steering_task::work()
{
    switch (m_state) {
    case STEER: {
        int prev_task_id = m_database.get_steering_task_id(m_sta_mac);
        m_tasks.kill_task(prev_task_id);
        m_database.assign_steering_task_id(m_sta_mac, id);

        m_original_bssid = m_database.get_node_parent(m_sta_mac);
        m_ssid_name      = m_database.get_hostap_ssid(m_original_bssid);

        steer_sta();

        m_state = FINALIZE;
        if (m_steer_restricted) {
            finish();
        }
        wait_for_event(STA_DISCONNECTED);
        wait_for_event(STA_CONNECTED);
        set_events_timeout(STEERING_WAIT_TIME_MS);
        break;
    }

    case FINALIZE: {

        if (!m_steering_success && m_disassoc_imminent) {
            TASK_LOG(DEBUG) << "steering failed for " << m_sta_mac << " from " << m_original_bssid
                            << " to " << m_target_bssid;

            /*
                 * might need to split this logic to high and low bands of 5GHz
                 * since some clients can support one but not the other
                 */
            if (m_database.is_node_24ghz(m_original_bssid) &&
                m_database.is_node_5ghz(m_target_bssid)) {
                TASK_LOG(DEBUG) << "steering from 2.4GHz to 5GHz failed --> updating failed 5ghz "
                                   "steering attempt";
                m_database.update_node_failed_5ghz_steer_attempt(m_sta_mac);
            } else if (m_database.is_node_5ghz(m_original_bssid) &&
                       m_database.is_node_24ghz(m_target_bssid)) {
                TASK_LOG(DEBUG) << "steering from 5GHz to 2.4GHz failed, updating failed 2.4ghz "
                                   "steering attempt";
                m_database.update_node_failed_24ghz_steer_attempt(m_sta_mac);
            }
        }

        print_steering_info();

        if (m_database.config.persistent_db) {
            // Set is-unfriendly flag only if client exists in the persistent DB.
            auto client_mac = tlvf::mac_from_string(m_sta_mac);
            if (m_database.is_client_in_persistent_db(client_mac)) {
                m_database.set_client_is_unfriendly(client_mac, !m_steering_success);
            }
        }

        finish();
        break;
    }

    default:
        break;
    }
}

void client_steering_task::steer_sta()
{
    if (m_database.get_node_type(m_sta_mac) != beerocks::TYPE_IRE_BACKHAUL) {
        if (!m_database.set_node_handoff_flag(m_sta_mac, true)) {
            LOG(ERROR) << "can't set handoff flag for " << m_sta_mac;
        }
    }

    std::string radio_mac = m_database.get_node_parent_radio(m_target_bssid);
    if (radio_mac.empty()) {
        LOG(ERROR) << "parent radio for target-bssid=" << m_target_bssid
                   << " not found, exiting steering task";
        return;
    }
    m_original_bssid = m_database.get_node_parent(m_sta_mac);

    // Send 17.1.27	Client Association Control Request
    if (!m_cmdu_tx.create(0,
                          ieee1905_1::eMessageType::CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE)) {
        LOG(ERROR)
            << "cmdu creation of type CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE, has failed";
        return;
    }

    auto association_control_request_tlv =
        m_cmdu_tx.addClass<wfa_map::tlvClientAssociationControlRequest>();
    if (!association_control_request_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvClientAssociationControlRequest failed";
        return;
    }

    association_control_request_tlv->bssid_to_block_client() =
        tlvf::mac_from_string(m_target_bssid);
    association_control_request_tlv->association_control() =
        wfa_map::tlvClientAssociationControlRequest::UNBLOCK;
    association_control_request_tlv->validity_period_sec() = 0;
    association_control_request_tlv->alloc_sta_list();
    auto sta_list_unblock         = association_control_request_tlv->sta_list(0);
    std::get<1>(sta_list_unblock) = tlvf::mac_from_string(m_sta_mac);

    auto agent_mac = m_database.get_node_parent_ire(radio_mac);
    if (agent_mac.empty()) {
        LOG(ERROR) << "parent ire for radio_mac=" << radio_mac
                   << " not found, exiting steering task";
        return;
    }
    TASK_LOG(DEBUG) << "sending allow request for " << m_sta_mac << " to bssid " << m_target_bssid
                    << " id=" << int(id);
    son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac);

    // update bml listeners
    bml_task::client_allow_req_available_event client_allow_event;
    client_allow_event.sta_mac    = m_sta_mac;
    client_allow_event.hostap_mac = m_target_bssid;
    client_allow_event.ip         = m_database.get_node_ipv4(m_sta_mac);
    m_tasks.push_event(m_database.get_bml_task_id(), bml_task::CLIENT_ALLOW_REQ_EVENT_AVAILABLE,
                       &client_allow_event);

    if (m_database.get_node_type(m_sta_mac) == beerocks::TYPE_IRE_BACKHAUL) {
        TASK_LOG(DEBUG) << "SLAVE " << m_sta_mac
                        << " has an active socket, sending BACKHAUL_ROAM_REQUEST";
        auto roam_request =
            m_cmdu_tx.create(0, ieee1905_1::eMessageType::BACKHAUL_STEERING_REQUEST_MESSAGE);
        if (!roam_request) {
            LOG(ERROR) << "Failed building BACKHAUL_STEERING_REQUEST_MESSAGE!";
            return;
        }

        auto bh_steer_req_tlv = m_cmdu_tx.addClass<wfa_map::tlvBackhaulSteeringRequest>();
        if (!bh_steer_req_tlv) {
            LOG(ERROR) << "Failed building addClass<wfa_map::tlvSteeringRequest!";
            return;
        }

        bh_steer_req_tlv->backhaul_station_mac()  = tlvf::mac_from_string(m_sta_mac);
        bh_steer_req_tlv->target_bssid()          = tlvf::mac_from_string(m_target_bssid);
        bh_steer_req_tlv->target_channel_number() = m_database.get_node_channel(m_target_bssid);
        bh_steer_req_tlv->operating_class() =
            m_database.get_hostap_operating_class(tlvf::mac_from_string(m_target_bssid));
        bh_steer_req_tlv->finalize();

        son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, radio_mac);

        // update bml listeners
        bml_task::bh_roam_req_available_event bh_roam_event;
        bh_roam_event.bssid   = m_target_bssid;
        bh_roam_event.channel = m_database.get_node_channel(m_target_bssid);
        m_tasks.push_event(m_database.get_bml_task_id(), bml_task::BH_ROAM_REQ_EVENT_AVAILABLE,
                           &bh_roam_event);

        return;
    }

    auto hostaps                   = m_database.get_active_hostaps();
    std::string original_radio_mac = m_database.get_node_parent_radio(m_original_bssid);
    hostaps.erase(radio_mac); // remove chosen hostap from the general list
    for (auto &hostap : hostaps) {
        /*
        * send disallow to all others
        */
        const auto &hostap_vaps = m_database.get_hostap_vap_list(hostap);
        const auto &ssid        = m_database.get_hostap_ssid(m_target_bssid);
        for (const auto &hostap_vap : hostap_vaps) {
            if (hostap_vap.second.ssid != ssid) {
                continue;
            }

            agent_mac = m_database.get_node_parent_ire(hostap);
            if (!m_cmdu_tx.create(
                    0, ieee1905_1::eMessageType::CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE)) {
                LOG(ERROR) << "cmdu creation of type "
                              "CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE, has failed";
                return;
            }

            auto association_control_block_request_tlv =
                m_cmdu_tx.addClass<wfa_map::tlvClientAssociationControlRequest>();
            if (!association_control_block_request_tlv) {
                LOG(ERROR) << "addClass wfa_map::tlvClientAssociationControlRequest failed";
                return;
            }
            association_control_block_request_tlv->bssid_to_block_client() =
                tlvf::mac_from_string(hostap_vap.second.mac);
            association_control_block_request_tlv->association_control() =
                wfa_map::tlvClientAssociationControlRequest::BLOCK;
            association_control_block_request_tlv->validity_period_sec() =
                STEERING_WAIT_TIME_MS / 1000;
            association_control_block_request_tlv->alloc_sta_list();
            auto sta_list_block         = association_control_block_request_tlv->sta_list(0);
            std::get<1>(sta_list_block) = tlvf::mac_from_string(m_sta_mac);
            son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, hostap);
            TASK_LOG(DEBUG) << "sending disallow request for " << m_sta_mac << " to bssid "
                            << hostap_vap.second.mac << " with validity period = "
                            << association_control_block_request_tlv->validity_period_sec()
                            << "sec,  id=" << int(id);

            // update bml listeners
            bml_task::client_disallow_req_available_event client_disallow_event;
            client_disallow_event.sta_mac    = m_sta_mac;
            client_disallow_event.hostap_mac = hostap;
            m_tasks.push_event(m_database.get_bml_task_id(),
                               bml_task::CLIENT_DISALLOW_REQ_EVENT_AVAILABLE,
                               &client_disallow_event);
        }
    }

    // Send STEERING request
    if (!m_cmdu_tx.create(0, ieee1905_1::eMessageType::CLIENT_STEERING_REQUEST_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type CLIENT_STEERING_REQUEST_MESSAGE, has failed";
        return;
    }

    auto steering_request_tlv = m_cmdu_tx.addClass<wfa_map::tlvSteeringRequest>();

    if (!steering_request_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvSteeringRequest failed";
        return;
    }

    steering_request_tlv->request_flags().request_mode =
        wfa_map::tlvSteeringRequest::REQUEST_IS_A_STEERING_MANDATE_TO_TRIGGER_STEERING;
    steering_request_tlv->request_flags().btm_disassociation_imminent_bit = m_disassoc_imminent;

    steering_request_tlv->btm_disassociation_timer_ms() = m_disassoc_timer_ms;
    steering_request_tlv->bssid()                       = tlvf::mac_from_string(m_original_bssid);

    steering_request_tlv->alloc_sta_list();
    auto sta_list         = steering_request_tlv->sta_list(0);
    std::get<1>(sta_list) = tlvf::mac_from_string(m_sta_mac);

    steering_request_tlv->alloc_target_bssid_list();
    auto bssid_list                      = steering_request_tlv->target_bssid_list(0);
    std::get<1>(bssid_list).target_bssid = tlvf::mac_from_string(m_target_bssid);
    std::get<1>(bssid_list).target_bss_operating_class =
        m_database.get_hostap_operating_class(tlvf::mac_from_string(m_target_bssid));
    std::get<1>(bssid_list).target_bss_channel_number = m_database.get_node_channel(m_target_bssid);

    agent_mac = m_database.get_node_parent_ire(m_original_bssid);
    son_actions::send_cmdu_to_agent(agent_mac, m_cmdu_tx, m_database, original_radio_mac);
    TASK_LOG(DEBUG) << "sending steering request, sta " << m_sta_mac << " steer from bssid "
                    << m_original_bssid << " to bssid " << m_target_bssid << " channel "
                    << std::to_string(std::get<1>(bssid_list).target_bss_channel_number)
                    << " disassoc_timer=" << m_disassoc_timer_ms
                    << " m_disassoc_imminent=" << m_disassoc_imminent << " id=" << int(id);

    // update bml listeners
    bml_task::bss_tm_req_available_event bss_tm_event;
    bss_tm_event.target_bssid      = m_target_bssid;
    bss_tm_event.disassoc_imminent = m_disassoc_imminent;
    m_tasks.push_event(m_database.get_bml_task_id(), bml_task::BSS_TM_REQ_EVENT_AVAILABLE,
                       &bss_tm_event);
}

void client_steering_task::print_steering_info()
{
    // Get timestamp of date & time as a string
    char temp[70];
    std::string timestamp;
    auto now          = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm    = *std::localtime(&now_c);
    if (strftime(temp, sizeof(temp), "%c", &now_tm)) {
        timestamp = temp;
    }

    if (m_steering_type.empty()) {
        m_steering_type = std::string(" 11v (BTM) ");
        if (!m_database.get_node_11v_capability(m_sta_mac)) {
            m_steering_type = std::string(" Legacy ");
        }
    }
    LOG(INFO) << "Client Steer attempt: "
              << "result= " << (m_steering_success ? "Success " : "Failed")
              << ", sta_mac= " << m_sta_mac << ", source= " << m_original_bssid
              << ", dest= " << m_target_bssid << ", trigger=" << m_triggered_by
              << ", type=" << m_steering_type << ", SSID= " << m_ssid_name
              << ", time= " << timestamp;
}

void client_steering_task::handle_event(int event_type, void *obj)
{
    if (event_type == STA_CONNECTED) {
        auto connected_bssid = m_database.get_node_parent(m_sta_mac);
        if (m_target_bssid == connected_bssid) {
            TASK_LOG(DEBUG) << "steering successful for sta " << m_sta_mac << " to bssid "
                            << connected_bssid;
            m_steering_success = true;
        } else {
            TASK_LOG(ERROR) << "sta " << m_sta_mac << " steered to bssid " << connected_bssid
                            << " ,target bssid was " << m_target_bssid;
        }
    } else if (event_type == STA_DISCONNECTED) {
        TASK_LOG(DEBUG) << "sta " << m_sta_mac << " disconnected due to steering request";
    } else if (event_type == BSS_TM_REQUEST_REJECTED) {
        TASK_LOG(DEBUG) << "sta " << m_sta_mac << " rejected BSS_TM request";
        if (m_disassoc_imminent) {
            TASK_LOG(DEBUG) << "m_disassoc_imminent flag is true, proceeding as usual";
        } else {
            TASK_LOG(DEBUG) << "aborting task";
            print_steering_info();
            // need to remove client from blacklist ASAP and not wait until the disallow period ends.
            son_actions::unblock_sta(m_database, m_cmdu_tx, m_sta_mac);
            finish();
        }
    } else if (event_type == BTM_REPORT_RECEIVED) {
        m_btm_report_received = true;
    }
}

void client_steering_task::handle_task_end()
{
    if (!m_btm_report_received) {
        TASK_LOG(DEBUG) << "client didn't respond to 11v request, updating responsiveness";
        m_database.update_node_11v_responsiveness(m_sta_mac, false);
    }
    m_database.set_node_handoff_flag(m_sta_mac, false);
}
