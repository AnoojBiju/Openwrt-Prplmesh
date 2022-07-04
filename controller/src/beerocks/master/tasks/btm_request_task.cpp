/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "btm_request_task.h"
#include "../db/db_algo.h"
#include "../son_actions.h"
#include "bml_task.h"

#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <ctime>
#include <easylogging++.h>
#include <tlvf/wfa_map/tlvBackhaulSteeringRequest.h>
#include <tlvf/wfa_map/tlvClientAssociationControlRequest.h>
#include <tlvf/wfa_map/tlvSteeringRequest.h>

using namespace beerocks;
using namespace net;
using namespace son;

btm_request_task::btm_request_task(db &database, ieee1905_1::CmduMessageTx &cmdu_tx,
                                   task_pool &tasks, const std::string &sta_mac,
                                   const std::string &target_bssid, const std::string &triggered_by,
                                   bool disassoc_imminent, int validity_interval_ms,
                                   int steering_timer_ms, int disassoc_timer_ms,
                                   const std::string &task_name)
    : task(task_name), m_database(database), m_cmdu_tx(cmdu_tx), m_tasks(tasks), m_sta_mac(sta_mac),
      m_target_bssid(target_bssid), //Chosen VAP BSSID to steer the client to
      m_triggered_by(triggered_by), m_disassoc_imminent(disassoc_imminent),
      m_disassoc_timer_ms(disassoc_timer_ms), m_steering_timer_ms(steering_timer_ms)
{
}

void btm_request_task::work()
{
    switch (m_state) {
    case SEND_BTM_REQUEST: {
        auto station = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
        if (!station) {
            LOG(ERROR) << "Station " << m_sta_mac << " not found";
            finish();
            break;
        }

        int prev_task_id = station->btm_request_task_id;
        m_tasks.kill_task(prev_task_id);
        station->btm_request_task_id = id;

        auto original_bss = station->get_bss();
        if (!original_bss) {
            LOG(ERROR) << "Unable to get parent BSS for station " << m_sta_mac;
            finish();
            break;
        }

        m_original_bssid = tlvf::mac_to_string(original_bss->bssid);
        m_ssid_name      = original_bss->ssid;


        if (m_original_bssid == m_target_bssid) {
            TASK_LOG(DEBUG) << "Target and original BSSIDs are the same:" << m_target_bssid
                            << ". Aborting steering task.";
            m_steer_try_performed = false;
            if (m_database.get_node_11v_capability(*station)) {
                station->steering_summary_stats.btm_failures++;
                m_database.dm_increment_steer_summary_stats("BTMFailures");
            } else {
                station->steering_summary_stats.blacklist_failures++;
                m_database.dm_increment_steer_summary_stats("BlacklistFailures");
            }
            finish();
            break;
        }

        steer_sta();

        m_steering_start = std::chrono::steady_clock::now();
        update_sta_steer_attempt_stats(*station);

        m_state = FINALIZE;

        wait_for_event(STA_CONNECTED);
        wait_for_event(BTM_REPORT_RECEIVED);

        set_events_timeout(STEERING_WAIT_TIME_MS);
        break;
    }

    case FINALIZE: {
        auto client = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
        if (!client) {
            TASK_LOG(ERROR) << "Client " << m_sta_mac << " not found";
            finish();
            break;
        }

        if (!m_steering_success && m_disassoc_imminent) {
            TASK_LOG(DEBUG) << "Steering failed for " << m_sta_mac << " from " << m_original_bssid
                            << " to " << m_target_bssid;
            if (m_database.get_node_11v_capability(*client)) {
                client->steering_summary_stats.btm_failures++;
                m_database.dm_increment_steer_summary_stats("BTMFailures");
            } else {
                client->steering_summary_stats.blacklist_failures++;
                m_database.dm_increment_steer_summary_stats("BlacklistFailures");
            }
            /*
            * might need to split this logic to high and low bands of 5GHz
            * since some clients can support one but not the other
            */
            if (m_database.is_node_24ghz(m_original_bssid) &&
                m_database.is_node_5ghz(m_target_bssid)) {
                TASK_LOG(DEBUG) << "Steering from 2.4GHz to 5GHz failed --> updating failed 5ghz "
                                   "steering attempt";
                m_database.update_node_failed_5ghz_steer_attempt(m_sta_mac);
            } else if (m_database.is_node_5ghz(m_original_bssid) &&
                       m_database.is_node_24ghz(m_target_bssid)) {
                TASK_LOG(DEBUG) << "Steering from 5GHz to 2.4GHz failed, updating failed 2.4ghz "
                                   "steering attempt";
                m_database.update_node_failed_24ghz_steer_attempt(m_sta_mac);
            }
        } else {
            if (m_database.get_node_11v_capability(*client)) {
                client->steering_summary_stats.btm_successes++;
                m_database.dm_increment_steer_summary_stats("BTMSuccesses");
            } else {
                client->steering_summary_stats.blacklist_successes++;
                m_database.dm_increment_steer_summary_stats("BlacklistSuccesses");
            }
        }

        if (!dm_set_steer_event_params(m_database.dm_add_steer_event())) {
            LOG(ERROR) << "Failed to set parameters of Device.WiFi.DataElements.SteerEvent";
        }

        if (!add_sta_steer_event_to_db()) {
            LOG(ERROR) << "Failed to add MultiAPSTA.SteeringHistory for STA in database";
        }
        m_database.dm_restore_steering_summary_stats(*client);

        print_steering_info();

        if (m_database.config.persistent_db) {

            // Set is-unfriendly flag only if client exists in the persistent DB.
            auto client_mac = tlvf::mac_from_string(m_sta_mac);
            if (m_database.is_client_in_persistent_db(client_mac)) {
                m_database.set_client_is_unfriendly(*client, !m_steering_success);
            }
        }

        finish();
        break;
    }

    default:
        break;
    }
}

void btm_request_task::steer_sta()
{
    auto client = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
    if (!client) {
        LOG(ERROR) << "Client " << m_sta_mac << " not found";
    }

    if (m_database.get_node_type(m_sta_mac) != beerocks::TYPE_IRE_BACKHAUL) {
        if (client && !m_database.set_node_handoff_flag(*client, true)) {
            LOG(ERROR) << "Can't set handoff flag for " << m_sta_mac;
        }
    }

    auto target_agent = m_database.get_agent_by_bssid(tlvf::mac_from_string(m_target_bssid));
    if (!target_agent || tlvf::mac_to_string(target_agent->al_mac).empty()) {
        LOG(ERROR) << "Parent agent for bssid= " << m_target_bssid
                   << " not found, exiting steering task";
        return;
    }

    if (client) {
        dm_update_multi_ap_steering_params(m_database.get_node_11v_capability(*client));
    }
    // Send 17.1.27	Client Association Control Request
    std::unordered_set<sMacAddr> unblock_list{tlvf::mac_from_string(m_sta_mac)};

    son_actions::send_client_association_control(
        m_database, m_cmdu_tx, target_agent->al_mac, tlvf::mac_from_string(m_target_bssid),
        unblock_list, 0, wfa_map::tlvClientAssociationControlRequest::UNBLOCK);

    // update bml listeners
    bml_task::client_allow_req_available_event client_allow_event;
    client_allow_event.sta_mac    = m_sta_mac;
    client_allow_event.hostap_mac = m_target_bssid;
    client_allow_event.ip         = m_database.get_node_ipv4(m_sta_mac);
    m_tasks.push_event(m_database.get_bml_task_id(), bml_task::CLIENT_ALLOW_REQ_EVENT_AVAILABLE,
                       &client_allow_event);

    if (m_database.get_node_type(m_sta_mac) == beerocks::TYPE_IRE_BACKHAUL) {
        LOG(ERROR) << "Device with mac " << m_sta_mac
                   << " is of type Backhaul Station, do not use BTM Request";
        return;
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
    steering_request_tlv->request_flags().btm_abridged_bit                = 1;

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

    auto source_agent = m_database.get_agent_by_bssid(tlvf::mac_from_string(m_original_bssid));
    son_actions::send_cmdu_to_agent(source_agent->al_mac, m_cmdu_tx, m_database);
    TASK_LOG(DEBUG) << "Sending steering request, sta " << m_sta_mac << " steer from bssid "
                    << m_original_bssid << " to bssid " << m_target_bssid << " channel "
                    << std::to_string(std::get<1>(bssid_list).target_bss_channel_number)
                    << " disassoc_timer=" << m_disassoc_timer_ms
                    << " disassoc_imminent=" << m_disassoc_imminent << " id=" << int(id);

    m_steer_try_performed = true;

    // update bml listeners
    bml_task::bss_tm_req_available_event bss_tm_event;
    bss_tm_event.target_bssid      = m_target_bssid;
    bss_tm_event.disassoc_imminent = m_disassoc_imminent;
    m_tasks.push_event(m_database.get_bml_task_id(), bml_task::BSS_TM_REQ_EVENT_AVAILABLE,
                       &bss_tm_event);
}

void btm_request_task::print_steering_info()
{
    // Get timestamp of date & time as a string
    time_t now            = time(NULL);
    std::string timestamp = ctime(&now);

    auto client = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
    if (!client) {
        LOG(ERROR) << "Client " << m_sta_mac << " is not found";
        return;
    }

    if (m_steering_type.empty()) {
        m_steering_type = std::string(" 11v (BTM) ");
        if (!m_database.get_node_11v_capability(*client)) {
            m_steering_type = std::string(" Legacy ");
        }
    }
    LOG(INFO) << "Btmreq Client Steer attempt: "
              << "result= " << (m_steering_success ? "Success " : "Failed")
              << ", sta_mac= " << m_sta_mac << ", source= " << m_original_bssid
              << ", dest= " << m_target_bssid << ", trigger=" << m_triggered_by
              << ", type=" << m_steering_type << ", SSID= " << m_ssid_name
              << ", time= " << timestamp;
}

void btm_request_task::handle_event(int event_type, void *obj)
{
    if (event_type == STA_CONNECTED) {

        auto station       = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
        auto connected_bss = station->get_bss();

        if (tlvf::mac_to_string(connected_bss->bssid) == m_target_bssid) {
            TASK_LOG(DEBUG) << "steering successful for sta " << m_sta_mac << " to bssid "
                            << connected_bss->bssid;
            m_steering_success = true;

            m_status_code = wfa_map::tlvSteeringBTMReport::ACCEPT;
            // station connected to the target bssid implies status::ACCEPT

            if (m_steering_start.time_since_epoch().count() &&
                m_steering_start < std::chrono::steady_clock::now()) {
                m_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - m_steering_start);
                m_steering_start = {};
            }

        } else {
            TASK_LOG(ERROR) << "sta " << m_sta_mac << " steered to bssid " << connected_bss->bssid
                            << " ,target bssid was " << m_target_bssid;
        }

    } else if (event_type == STA_DISCONNECTED) {
        TASK_LOG(DEBUG) << "sta " << m_sta_mac << " disconnected due to steering request";
    } else if (event_type == BTM_REPORT_RECEIVED) {
        m_btm_report_received = true;
        m_status_code         = *(wfa_map::tlvSteeringBTMReport::eBTMStatusCode *)obj;

        LOG(DEBUG) << "status code " << int(m_status_code);
    }
}

void btm_request_task::handle_task_end()
{
    auto client = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
    if (!client) {
        LOG(ERROR) << "Client " << m_sta_mac << " is not found";
        return;
    }

    if (m_steer_try_performed && !m_btm_report_received) {
        TASK_LOG(DEBUG) << "client didn't respond to 11v request, updating responsiveness";
        m_database.update_node_11v_responsiveness(*client, false);
    }
    m_database.set_node_handoff_flag(*client, false);
}

bool btm_request_task::dm_set_steer_event_params(const std::string &event_path)
{
    if (event_path.empty()) {
        return false;
    }

    auto ambiorix_dm = m_database.get_ambiorix_obj();

    if (!ambiorix_dm) {
        LOG(ERROR) << "Failed to get Controller Data Model object.";
        return false;
    }

    m_dm_timestamp = ambiorix_dm->get_datamodel_time_format();

    ambiorix_dm->set(event_path, "DeviceId", m_sta_mac);
    ambiorix_dm->set(event_path, "SteeredFrom", m_original_bssid);
    ambiorix_dm->set(event_path, "SteeredTo", m_target_bssid);
    ambiorix_dm->set(event_path, "StatusCode", m_status_code);
    ambiorix_dm->set(event_path, "TimeStamp", m_dm_timestamp);

    m_database.dm_set_status(event_path, m_status_code);

    if (m_steering_success) {
        ambiorix_dm->set(event_path, "Result", std::string("Success"));
        ambiorix_dm->set(event_path, "TimeTaken", m_duration.count());

        int8_t rx_rssi = 0, rx_packets = 0;

        auto station = m_database.get_station(tlvf::mac_from_string(m_sta_mac));
        if (!station) {
            LOG(ERROR) << "Station " << m_sta_mac << " not found";
            return false;
        }

        if (!station->get_cross_rx_rssi(m_target_bssid, rx_rssi, rx_packets)) {
            TASK_LOG(ERROR) << "can't get cross_rx_rssi for bssid =" << m_target_bssid;
        }
        ambiorix_dm->set(event_path, "NewLinkRate", rx_rssi);
    } else {
        ambiorix_dm->set(event_path, "Result", std::string("Fail"));
    }

    std::string steer_origin = "Unknown";
    std::string steer_type   = "Unknown";

    // For the time being, Agent doesn't steer, skip setting Agent steer origin.
    if (std::chrono::duration_cast<std::chrono::seconds>(m_duration).count() < 10) {
        // If the duration is smaller than some compile-time defined threshold,
        // e.g. 10s, it is considered a steering event originated by the station
        steer_origin = "Station";
    }
    if (m_triggered_by.find("CLI") != std::string::npos) {
        steer_origin = "CLI";
    }
    if (m_triggered_by.find("NBAPI") != std::string::npos) {
        steer_origin = "NBAPI";
    }
    if (m_triggered_by.find("optimal_path_task") != std::string::npos ||
        m_triggered_by.find("DFS Rentry") != std::string::npos) {
        steer_origin = "Controller";

        // Steering type is always BTM if the controller initiated
        // the steering, and unknown otherwise.
        ambiorix_dm->set(event_path, "SteeringType", std::string("BTM"));
        steer_type = "BTM";
    }
    ambiorix_dm->set(event_path, "SteeringOrigin", steer_origin);
    if (m_database.config.persistent_db) {
        add_steer_history_to_persistent_db(steer_origin, steer_type);
    }
    return true;
}

void btm_request_task::add_steer_history_to_persistent_db(const std::string &steer_origin,
                                                          const std::string &steer_type)
{
    db::ValuesMap values_map;

    values_map["device_id"]       = m_sta_mac;
    values_map["steered_from"]    = m_original_bssid;
    values_map["time_stamp"]      = m_dm_timestamp;
    values_map["steered_to"]      = m_target_bssid;
    values_map["time_taken"]      = "0";
    values_map["steering_type"]   = steer_type;
    values_map["steering_origin"] = steer_origin;
    values_map["result"]          = "Fail";
    if (m_steering_success) {
        values_map["result"]     = "Success";
        values_map["time_taken"] = std::to_string(m_duration.count());
    }
    if (!m_database.add_steer_event_to_persistent_db(values_map)) {
        LOG(ERROR) << "Failed to save steer_history to persistent db.";
    }
}

void btm_request_task::dm_update_multi_ap_steering_params(bool sta_11v_capable)
{
    auto bss_path = m_database.get_node_data_model_path(m_target_bssid);

    if (bss_path.empty()) {
        LOG(WARNING) << "Path for BSS " << m_target_bssid << " not set";
        return;
    }

    if (m_steering_type.find("BTM") != std::string::npos ||
        (m_steering_type.empty() && sta_11v_capable)) {
        m_database.dm_uint64_param_one_up(bss_path + ".MultiAPSteering", "BTMAttempts");
        m_database.dm_increment_steer_summary_stats("BTMAttempts");
        m_database.dm_uint64_param_one_up(bss_path + ".MultiAPSteering", "BlacklistAttempts");
        m_database.dm_increment_steer_summary_stats("BlacklistAttempts");
    }
}

bool btm_request_task::add_sta_steer_event_to_db()
{
    db::sStaSteeringEvent steer_sta_event;

    steer_sta_event.timestamp = m_dm_timestamp;

    steer_sta_event.original_bssid = tlvf::mac_from_string(m_original_bssid);
    steer_sta_event.target_bssid   = tlvf::mac_from_string(m_target_bssid);
    if (m_steering_success) {
        steer_sta_event.duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(m_duration);
    } else {
        steer_sta_event.duration = {}; // a value of 0 is reserved for failed transitions
    }

    steer_sta_event.trigger_event = "Unknown";

    // TODO 11v Async BTM Query is not supported (PPM-1611)
    // And Blacklist events can not be identified
    steer_sta_event.steering_approach = "BTM Request";

    if (m_triggered_by.find("backhaul") != std::string::npos) {
        steer_sta_event.trigger_event = "Backhaul Link Utilization";

    } else if (m_triggered_by.find("DFS Rentry") != std::string::npos) {
        steer_sta_event.trigger_event = "Wi-Fi Channel Utilization";

    } else if (m_triggered_by.find("optimal_path_task") != std::string::npos) {
        steer_sta_event.trigger_event = "Wi-Fi Link Quality";

    } else if (m_triggered_by.find("NBAPI") != std::string::npos) {
        steer_sta_event.trigger_event = "Northbound API";
    }

    return m_database.add_sta_steering_event(tlvf::mac_from_string(m_sta_mac), steer_sta_event);
}

void btm_request_task::update_sta_steer_attempt_stats(Station &station)
{
    auto ambiorix_dm = m_database.get_ambiorix_obj();

    if (!ambiorix_dm) {
        LOG(ERROR) << "Failed to get Controller Data Model object.";
        return;
    }
    /*
        Set value for LastSteerTime parameter - it is time of last steering attempt.
        When someone will try to get data from this parameter action method will 
        calculate time in seconds from last steering attempt.
    */

    station.steering_summary_stats.last_steer_time = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(m_steering_start.time_since_epoch())
            .count());
    ambiorix_dm->set(station.dm_path + ".MultiAPSTA.SteeringSummaryStats", "LastSteerTime",
                     station.steering_summary_stats.last_steer_time);

    if (m_database.get_node_11v_capability(station)) {
        station.steering_summary_stats.btm_attempts++;
        m_database.dm_increment_steer_summary_stats("BTMAttempts");
    } else {
        station.steering_summary_stats.blacklist_attempts++;
        m_database.dm_increment_steer_summary_stats("BlacklistAttempts");
    }
}

bool btm_request_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                             ieee1905_1::CmduMessageRx &cmdu_rx)
{
    return false;
}
