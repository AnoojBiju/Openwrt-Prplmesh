/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "optimal_path_task.h"
#include "../db/db_algo.h"
#include "../son_actions.h"

#include <bcl/beerocks_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <easylogging++.h>

#include <beerocks/tlvf/beerocks_message.h>

using namespace beerocks;
using namespace net;
using namespace son;

#define MAX_REQUEST_CYCLES 2
#define RX_RSSI_MEASUREMENT_REQUEST_TIMEOUT_MSEC 3000
#define BEACON_MEASUREMENT_REQUEST_TIMEOUT_MSEC 6000
#define DELAY_COUNT_LIMIT 2
#define DELTA_BURST_LIMIT 20
#define DEC_WINDOW_LIMIT 20
#define MAX_WINDOW_SIZE 200
#define MIN_WINDOW_SIZE 40
#define INC_DEC_WINDOW_STEPS 20
#define ONE_PERCENT 0.01f
#define EIGHTY_PERCENT 0.80f

/*
* Responsiveness may be less than 100% since the station might refuse to the measurement
* request or failed to measure it due to incapability (to measure in another band for
* example), missed the probe or due to the AP bad reception.
* There is a high probability to get responsiveness less than 100% and therefore, the
* threshold was changed to 50% as part of demo optimizations.
* This hardcoded threshold is temporary and shall be revised in the future.
* update: increasing to 80% since in bandsteering scenario there are only 2 radios
* and 50% means optimal path always will fail to find an additional candidate.
*/
static constexpr uint8_t RESPONSIVENESS_PRECENT_11K_THRESHOLD = 80;

/////////////// FOR DEBUG ONLY ////////////////
int optimal_path_task::cli_beacon_request_duration  = -1;
int optimal_path_task::cli_beacon_request_rand_ival = -1;
beerocks::eMeasurementMode11K optimal_path_task::cli_beacon_request_mode =
    beerocks::MEASURE_MODE_UNDEFINED;
///////////////////////////////////////////////

optimal_path_task::optimal_path_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                     task_pool &tasks_, const std::string &sta_mac_,
                                     int starting_delay_ms_, const std::string &task_name_)
    : task(task_name_), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_), sta_mac(sta_mac_),
      starting_delay_ms(starting_delay_ms_)
{
}

void optimal_path_task::work()
{
    bool task_enabled = true;

    auto station = database.get_station(tlvf::mac_from_string(sta_mac));
    if (!station) {
        TASK_LOG(ERROR) << "station " << sta_mac << " not found";
        finish();
        return;
    }

    if ((database.get_node_type(sta_mac) == beerocks::TYPE_CLIENT) &&
        (!database.settings_client_band_steering()) &&
        (!database.settings_client_optimal_path_roaming()) &&
        (!database.settings_client_11k_roaming())) {
        LOG_CLI(DEBUG, "Band steering:"
                           << database.settings_client_band_steering() << " | Optimal path roaming:"
                           << database.settings_client_optimal_path_roaming()
                           << " | 11k client roaming:" << database.settings_client_11k_roaming()
                           << " | Roaming decision on signal strength preference:"
                           << database.settings_client_optimal_path_roaming_prefer_signal_strength()
                           << " | Roaming RX RSSI cutoff:"
                           << database.config.roaming_rssi_cutoff_db);
        task_enabled = false;
    } else if (database.get_node_type(sta_mac) == beerocks::TYPE_IRE_BACKHAUL) {
        if (started_as_client) {
            LOG_CLI(DEBUG, sta_mac << " client changed to IRE, killing task");
            task_enabled = false;
        } else if (!database.settings_ire_roaming()) {
            LOG_CLI(DEBUG, sta_mac << " IRE roaming disabled, killing task");
            task_enabled = false;
        }
    } else if (station->confined) {
        LOG_CLI(DEBUG, sta_mac << " is confined to current AP, killing task");
        task_enabled = false;
    }
    if (!task_enabled) {
        finish();
        return;
    }

    switch (state) {
    case START: {

        current_hostap_vap = database.get_node_parent(sta_mac);
        // Steering allowed on all vaps unless load_steer_on_vaps list is defined
        // on the platform , in that case verify that vap is on that list
        if (!database.is_vap_on_steer_list(tlvf::mac_from_string(current_hostap_vap))) {
            TASK_LOG(WARNING) << "client " << sta_mac << " is connected to vap "
                              << current_hostap_vap << " that is currently not in steer list: "
                              << database.config.load_steer_on_vaps << " aborting optimal task";
            finish();
            return;
        }

        if (database.get_node_handoff_flag(*station)) {
            LOG_CLI(DEBUG, sta_mac << " is already in handoff, killing task");
            finish();
            return;
        }

        measurement_request = {};

        int prev_task_id = station->roaming_task_id;
        tasks.kill_task(prev_task_id);
        station->roaming_task_id = id;

        if (database.get_node_type(sta_mac) == beerocks::TYPE_CLIENT) {
            started_as_client = true;
        }

        if (!database.settings_client_optimal_path_roaming() &&
            !database.settings_client_band_steering()) {
            TASK_LOG(DEBUG) << "settings_client_optimal_path_roaming and band steering is not "
                               "enabled! FINISH TASK";
            finish();
            return;
        }

        current_hostap      = database.get_node_parent_radio(current_hostap_vap);
        current_hostap_ssid = database.get_hostap_ssid(tlvf::mac_from_string(current_hostap_vap));

        sta_support_11k = database.settings_client_11k_roaming() &&
                          (database.get_node_beacon_measurement_support_level(sta_mac) !=
                           BEACON_MEAS_UNSUPPORTED);

        //// only for debug ////
        TASK_LOG(DEBUG) << "sta_support_11k=" << int(sta_support_11k);
        TASK_LOG(DEBUG) << "sta_support_beacon_measurement="
                        << int(database.get_node_beacon_measurement_support_level(sta_mac))
                        << ", sta_mac=" << sta_mac;
        if (!database.settings_client_11k_roaming()) {
            TASK_LOG(DEBUG) << "settings_client_11k_roaming is not enabled!";
        }
        if (database.get_node_beacon_measurement_support_level(sta_mac) ==
            BEACON_MEAS_UNSUPPORTED) {
            TASK_LOG(DEBUG) << "station " << sta_mac << " doesn't support beacon measurement!";
        }
        //////////////////////

        calculate_measurement_delay_count = 0;

        if (sta_support_11k) {
            state = FILL_POTENTIAL_AP_LIST_11K;
        } else if (database.settings_front_measurements() ||
                   database.settings_backhaul_measurements()) {
            state = FILL_POTENTIAL_AP_LIST_CROSS;
        } else {
            TASK_LOG(INFO) << "neither cross nor 11k are supported";
            finish();
        }
        wait_for(starting_delay_ms);
        break;
    }
    case FILL_POTENTIAL_AP_LIST_11K: {
        if (!assert_original_parent()) {
            TASK_LOG(INFO) << sta_mac << " no longer connected to " << current_hostap_vap
                           << " aborting task";
            finish();
            return;
        }

        // build pending mac list //
        auto agents  = database.get_all_connected_agents();
        auto subtree = database.get_node_subtree(sta_mac);

        std::vector<std::shared_ptr<Agent>> agents_outside_subtree;

        // insert all ires that outside the subtree to "agents_outside_subtree",
        // because it is impossible to move ire to a child ire. station doesn't has subtree.
        std::copy_if(agents.begin(), agents.end(), std::back_inserter(agents_outside_subtree),
                     [&](std::shared_ptr<Agent> agent) {
                         return (subtree.find(tlvf::mac_to_string(agent->al_mac)) == subtree.end());
                     });

        potential_11k_aps.clear();

        for (const auto &agent : agents_outside_subtree) {
            for (const auto &radio_map_element : agent->radios) {
                int8_t rx_rssi, dummy;
                auto radio       = radio_map_element.second;
                auto hostap      = tlvf::mac_to_string(radio->radio_uid);
                bool sta_is_5ghz = database.is_node_5ghz(sta_mac);
                station->get_cross_rx_rssi(current_hostap, rx_rssi, dummy);
                if ((!database.is_hostap_active(tlvf::mac_from_string(hostap))) ||
                    (!check_if_sta_can_steer_to_ap(hostap)) ||
                    (database.settings_client_optimal_path_roaming_prefer_signal_strength() &&
                     sta_is_5ghz && database.is_ap_out_of_band(hostap, sta_mac) &&
                     rx_rssi > database.config.roaming_rssi_cutoff_db)) {
                    continue;
                }
                if (!is_hostap_on_cs_process(hostap)) {
                    TASK_LOG(DEBUG) << sta_mac << " inserting new hostap to list: " << hostap;
                    potential_11k_aps.insert({hostap, false});
                }
            }
        }

        // Check if hostap has suitable ssid
        auto it = potential_11k_aps.begin();
        while (it != potential_11k_aps.end()) {

            std::string candidate_bssid = database.get_hostap_vap_with_ssid(
                tlvf::mac_from_string(it->first), current_hostap_ssid);

            if (candidate_bssid.empty()) {
                LOG(INFO) << "Remove candidate " << it->first
                          << ". Hostap doesn't have current_hostap_ssid " << current_hostap_ssid;
                it = potential_11k_aps.erase(it);
                continue;
            }

            // Steering allowed on all vaps unless load_steer_on_vaps list is defined
            // on the platform , in that case verify that vap is on that list
            if (!database.is_vap_on_steer_list(tlvf::mac_from_string(candidate_bssid))) {
                TASK_LOG(INFO) << "Remove candidate " << it->first << " , vap " << candidate_bssid
                               << " is not in steer list: " << database.config.load_steer_on_vaps;
                it = potential_11k_aps.erase(it);
            } else {
                ++it;
            }
        }

        // Check client's steering persistant database for any band/radio/device restrictions
        auto client = tlvf::mac_from_string(sta_mac);
        if (station->stay_on_initial_radio == eTriStateBool::TRUE) {
            TASK_LOG(INFO) << "Client stay on initial radio enabled";
            auto client_initial_radio = station->initial_radio;

            if (client_initial_radio == tlvf::mac_from_string(current_hostap)) {
                TASK_LOG(INFO) << "Client is already on initial radio " << client_initial_radio;
                finish();
                break;
            }
            // Client is not on initial radio, lets try to find it in the steering potential candidate list
            if (potential_11k_aps.find(tlvf::mac_to_string(client_initial_radio)) !=
                potential_11k_aps.end()) {
                // Initial client hostap is on the candidate list, force steer the client there.
                chosen_bssid =
                    database.get_hostap_vap_with_ssid(client_initial_radio, current_hostap_ssid);
                state          = SEND_STEER_ACTION;
                is_force_steer = true;

                chosen_method.append("Steer client imminently to initial radio " +
                                     tlvf::mac_to_string(client_initial_radio) + " ");
                // The following log print is used by the automated testing
                // Please do NOT change
                TASK_LOG(INFO) << "Resolving Optimal task on persistent preference: "
                               << chosen_method;
                break;
            }
            TASK_LOG(WARNING) << "Client's initial radio " << client_initial_radio
                              << " is not on the candidate ap list, continue as usual.";
        }

        auto selected_bands = station->selected_bands;
        if ((selected_bands != PARAMETER_NOT_CONFIGURED) &&
            (selected_bands != eClientSelectedBands::eSelectedBands_Disabled)) {
            TASK_LOG(INFO) << "Client stay on selected bands enabled";
            if (!database.is_hostap_on_client_selected_bands(
                    client, tlvf::mac_from_string(current_hostap))) {
                TASK_LOG(INFO) << "Current radio " << current_hostap
                               << " is not on one of client's selected bands "
                               << int(station->selected_bands);
                // Try to find radio with selected bands first on local device (same device the client
                // is currently connected on) and force steer the client to that radio.
                auto current_hostap_siblings = database.get_node_siblings(current_hostap);
                auto sibling_it =
                    std::find_if(current_hostap_siblings.begin(), current_hostap_siblings.end(),
                                 [&](const std::string &sibling) {
                                     return database.is_hostap_on_client_selected_bands(
                                         client, tlvf::mac_from_string(sibling));
                                 });

                if (sibling_it != current_hostap_siblings.end()) {
                    chosen_bssid = database.get_hostap_vap_with_ssid(
                        tlvf::mac_from_string(sibling_it->data()), current_hostap_ssid);
                    state          = SEND_STEER_ACTION;
                    is_force_steer = true;
                    chosen_method.append("Found local radio " + std::string(sibling_it->data()) +
                                         " on selected bands, force steer client to that radio ");
                    // The following log print is used by the automated testing
                    // Please do NOT change
                    TASK_LOG(INFO)
                        << "Resolving Optimal task on persistent preference: " << chosen_method;
                    break;
                }
                TASK_LOG(WARNING) << "Couldnt find local radio on selected bands "
                                  << int(station->selected_bands) << " with same client's ssid "
                                  << current_hostap_ssid;
            }
            // In case client is already connected to one of the selected bands
            // continue with optimal path task but remove all non selected band hostaps
            // from steering candidate list.
            remove_all_client_non_selected_band_radios(potential_11k_aps, client);
        }

        // hostap's list is ready , lets check if we have candidates left
        const auto hostap_candidates_size = potential_11k_aps.size();
        if (hostap_candidates_size == 0) {
            TASK_LOG(WARNING) << "Candidates list is empty, aborting optimal path task";
            database.dm_uint64_param_one_up(station->dm_path + ".MultiAPSteeringSummaryStats",
                                            "NoCandidateAPFailures");
            database.dm_uint64_param_one_up(
                "Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats",
                "NoCandidateAPFailures");
            finish();
            break;
        }

        if ((hostap_candidates_size == 1) && (potential_11k_aps.begin()->first == current_hostap)) {
            TASK_LOG(WARNING)
                << "Current hostap " << current_hostap
                << "is the only steering candidate left on the list, aborting optimal path task";
            database.dm_uint64_param_one_up(station->dm_path + ".MultiAPSteeringSummaryStats",
                                            "NoCandidateAPFailures");
            database.dm_uint64_param_one_up(
                "Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats",
                "NoCandidateAPFailures");
            finish();
            break;
        }

        potential_ap_iter = potential_11k_aps.begin();
        //initialize default 11k request params
        measurement_request.sta_mac          = tlvf::mac_from_string(sta_mac);
        measurement_request.measurement_mode = beerocks::MEASURE_MODE_ACTIVE;
        measurement_request.rand_ival = beerocks::BEACON_MEASURE_DEFAULT_RANDOMIZATION_INTERVAL;
        measurement_request.duration  = beerocks::BEACON_MEASURE_DEFAULT_ACTIVE_DURATION;
        measurement_request.sta_mac   = tlvf::mac_from_string(sta_mac);
        current_agent_mac             = database.get_node_parent_ire(current_hostap);

        iterator_element_counter = 1; // initialize counter value
        state                    = REQUEST_11K_MEASUREMENTS_BY_BSSID;
        break;
    }
    case REQUEST_11K_MEASUREMENTS_BY_BSSID: {

        if (!assert_original_parent()) {
            TASK_LOG(INFO) << sta_mac << " no longer connected to " << current_hostap_vap
                           << " aborting task";
            finish();
            return;
        }

        if (valid_beacon_measurement_report_count == potential_11k_aps.size()) {
            TASK_LOG(TRACE) << "go to state: FIND_AND_PICK_HOSTAP_11K";
            state = FIND_AND_PICK_HOSTAP_11K;
        } else {

            do {

                if (beacon_measurement_request_cycle_count < MAX_REQUEST_CYCLES &&
                    potential_ap_iter == potential_11k_aps.end()) {
                    potential_ap_iter        = potential_11k_aps.begin();
                    iterator_element_counter = 1;
                    beacon_measurement_request_cycle_count++;
                }

                TASK_LOG(TRACE) << "state: REQUEST_11K_MEASUREMENTS_BY_BSSID request_cycle="
                                << int(beacon_measurement_request_cycle_count)
                                << ", iterator_element_counter=" << int(iterator_element_counter)
                                << " out of " << int(potential_11k_aps.size());

                if (beacon_measurement_request_cycle_count == MAX_REQUEST_CYCLES) {
                    TASK_LOG(DEBUG) << "goto state: FIND_AND_PICK_HOSTAP_11K";
                    state = FIND_AND_PICK_HOSTAP_11K;
                    break;
                }

                auto ap_mac               = potential_ap_iter->first;
                bool is_valid_measurement = potential_ap_iter->second;
                if (!is_valid_measurement) { // this ap measurement was not received
                    if (ap_mac == current_hostap && beacon_measurement_request_cycle_count > 0) {
                        measurement_request.measurement_mode = beerocks::MEASURE_MODE_PASSIVE;
                        measurement_request.duration =
                            beerocks::BEACON_MEASURE_DEFAULT_PASSIVE_DURATION;
                    } else {
                        measurement_request.measurement_mode = beerocks::MEASURE_MODE_ACTIVE;
                        measurement_request.duration =
                            beerocks::BEACON_MEASURE_DEFAULT_ACTIVE_DURATION;
                    }
                    // ap_mac is a radio mac, but we need to request measurement on some vap since radio don't beacon
                    const std::string vap_mac = database.get_hostap_vap_with_ssid(
                        tlvf::mac_from_string(ap_mac), current_hostap_ssid);
                    if (vap_mac.empty()) {
                        LOG(ERROR) << "Failed to get vap for client beacon request, skipping "
                                      "measurement for "
                                   << ap_mac;
                        ++iterator_element_counter;
                        ++potential_ap_iter;
                        continue;
                    }
                    measurement_request.bssid   = tlvf::mac_from_string(vap_mac);
                    measurement_request.channel = database.get_node_channel(ap_mac);
                    measurement_request.op_class =
                        database.get_hostap_operating_class(tlvf::mac_from_string(ap_mac));
                    measurement_request.expected_reports_count = 1;

                    /////////////// FOR DEBUG ONLY ////////////////
                    use_cli_value = false;
                    if (cli_beacon_request_duration != -1) {
                        measurement_request.duration = cli_beacon_request_duration;
                        use_cli_value                = true;
                    }
                    if (cli_beacon_request_rand_ival != -1) {
                        measurement_request.rand_ival = cli_beacon_request_rand_ival;
                        use_cli_value                 = true;
                    }
                    if (cli_beacon_request_mode != beerocks::MEASURE_MODE_UNDEFINED) {
                        measurement_request.measurement_mode = cli_beacon_request_mode;
                        use_cli_value                        = true;
                    }
                    ///////////////////////////////////////////////

                    add_pending_mac(current_hostap,
                                    beerocks_message::ACTION_CONTROL_CLIENT_BEACON_11K_RESPONSE);
                    TASK_LOG(DEBUG)
                        << "requested 11K beacon measurement request from sta: " << sta_mac
                        << " on bssid: " << vap_mac;
                    auto request = message_com::create_vs_message<
                        beerocks_message::cACTION_CONTROL_CLIENT_BEACON_11K_REQUEST>(cmdu_tx, id);

                    if (request == nullptr) {
                        LOG(ERROR)
                            << "Failed building ACTION_CONTROL_CLIENT_BEACON_11K_REQUEST message!";
                        break;
                    }
                    request->params() = measurement_request;

                    son_actions::send_cmdu_to_agent(current_agent_mac, cmdu_tx, database,
                                                    current_hostap);

                    set_responses_timeout(BEACON_MEASUREMENT_REQUEST_TIMEOUT_MSEC);

                    ++iterator_element_counter;
                    ++potential_ap_iter;

                    break; // break do while loop to enter the state again after reponse received
                }

                ++iterator_element_counter;
                ++potential_ap_iter;

            } while (potential_ap_iter != potential_11k_aps.end());
        }
        break;
    }
    case FIND_AND_PICK_HOSTAP_11K: {
        if (!assert_original_parent()) {
            TASK_LOG(INFO) << sta_mac << " no longer connected to " << current_hostap_vap
                           << " aborting task";
            finish();
            return;
        }

        float responsiveness_precentage_11k =
            valid_beacon_measurement_report_count * 100.0 / potential_11k_aps.size();
        TASK_LOG(DEBUG) << "responsiveness_precentage_11k: " << int(responsiveness_precentage_11k)
                        << "%";

        if (responsiveness_precentage_11k < RESPONSIVENESS_PRECENT_11K_THRESHOLD) {
            TASK_LOG(DEBUG) << "11k measurement request responsiveness is less than "
                            << RESPONSIVENESS_PRECENT_11K_THRESHOLD << "%";
            if (database.settings_front_measurements()) {
                /////////////// FOR DEBUG ONLY ////////////////
                if (use_cli_value) {
                    TASK_LOG(DEBUG) << "used cli default values";
                    //finish();
                    //return;
                }
                ///////////////////////////////////////////////
                TASK_LOG(DEBUG) << "go to CROSS states";
                state = FILL_POTENTIAL_AP_LIST_CROSS;
                break;
            } else {
                TASK_LOG(DEBUG) << "front_measurements is not enabled --> finish task";
                finish();
                return;
            }
        }

        // The following log print is used by the automated testing
        // Please do NOT change
        TASK_LOG(DEBUG) << "Finished gathering 11k measurements";
        TASK_LOG(DEBUG) << "calculating estimate hostap dl rssi/rate for sta " << sta_mac;

        //calculate tx phy rate and find best_weighted_phy_rate
        int roaming_hysteresis_percent_bonus = database.config.roaming_hysteresis_percent_bonus;
        const beerocks::message::sRadioCapabilities *sta_capabilities;
        beerocks::message::sRadioCapabilities default_sta_cap;
        son::wireless_utils::sPhyUlParams current_ul_params;
        double hostap_phy_rate;
        double best_weighted_phy_rate              = 0;
        double best_weighted_phy_rate_below_cutoff = 0;
        int best_dl_rssi                           = beerocks::RSSI_MIN;
        int best_dl_rssi_below_cutoff              = beerocks::RSSI_MIN;
        bool all_hostaps_below_cutoff              = true;
        int best_dl_rssi_5g                        = beerocks::RSSI_MIN;
        int best_dl_rssi_2g                        = beerocks::RSSI_MIN;
        bool current_hostap_is_5ghz                = database.is_node_5ghz(current_hostap);
        std::string best_dl_rssi_hostap_5g;
        std::string best_dl_rssi_hostap_2g;
        std::string chosen_hostap_below_cutoff;

        int8_t current_hostap_rx_rssi, dummy_rx_packets;
        bool force_signal_strength_decision = false;
        bool current_below_cutoff           = false;

        if (!station->get_cross_rx_rssi(current_hostap, current_hostap_rx_rssi, dummy_rx_packets)) {
            TASK_LOG(ERROR) << "can't get cross_rx_rssi for hostap " << current_hostap;
        } else if (current_hostap_rx_rssi <= database.config.roaming_rssi_cutoff_db) {
            force_signal_strength_decision = true;
            current_below_cutoff           = true;
            TASK_LOG(DEBUG) << "forcing signal strength decision, current_hostap_rx_rssi="
                            << int(current_hostap_rx_rssi);
        }

        sticky_roaming_rssi = 0;

        for (const auto &it : potential_11k_aps) {
            auto hostap = it.first;

            bool estimate_dl_rssi = false;
            if (!it.second) { //missing beacon measurement
                if (hostap == current_hostap) {
                    estimate_dl_rssi = true;
                    LOG(DEBUG) << "didn't get beacon measurement data on current AP " << hostap
                               << ", estimating dl_rssi";
                } else {
                    LOG(DEBUG) << "didn't get beacon measurement data on AP " << hostap
                               << ", skipping";
                    continue;
                }
            }

            int hostap_channel  = database.get_node_channel(hostap);
            auto hostap_is_5ghz = database.is_node_5ghz(hostap);
            if (!force_signal_strength_decision &&
                !database.settings_client_optimal_path_roaming_prefer_signal_strength()) {
                // Get sta capabilities
                TASK_LOG(DEBUG) << "getting capabilities for sta_mac " << sta_mac << " on band "
                                << (hostap_is_5ghz ? "5GHz" : "2.4GHz");
                sta_capabilities = database.get_station_capabilities(sta_mac, hostap_is_5ghz);
                if (sta_capabilities == nullptr) {
                    TASK_LOG(WARNING) << "STA capabilities are empty - use default capabilities";
                    get_station_default_capabilities(hostap_is_5ghz, default_sta_cap);
                    sta_capabilities = &default_sta_cap;
                }

                TASK_LOG(DEBUG) << "sta_capabilities:"
                                << " ht_ss=" << int(sta_capabilities->ht_ss)
                                << " ht_mcs=" << int(sta_capabilities->ht_mcs)
                                << " vht_ss=" << int(sta_capabilities->vht_ss)
                                << " vht_mcs=" << int(sta_capabilities->vht_mcs)
                                << " ant_num=" << int(sta_capabilities->ant_num)
                                << " ht_bw=" << int(sta_capabilities->ht_bw)
                                << " vht_bw=" << int(sta_capabilities->vht_bw);

                auto hostap_bw = database.get_node_bw(hostap);

                int8_t dl_rssi;

                if (!estimate_dl_rssi) {
                    uint8_t dl_rcpi, dl_snr;
                    if (!station->get_beacon_measurement(hostap, dl_rcpi, dl_snr)) {
                        TASK_LOG(ERROR)
                            << "get_node_beacon_measurement() failed! sta_mac: " << sta_mac
                            << ", hostap: " << hostap;
                        continue;
                    }
                    dl_rssi = wireless_utils::convert_rssi_from_rcpi(dl_rcpi);

                    TASK_LOG(DEBUG) << "bssid " << hostap << " dl_rssi: " << int(dl_rssi)
                                    << ", dl_snr:" << int(dl_snr);
                } else {
                    int8_t rx_rssi, rx_packets;
                    if (!station->get_cross_rx_rssi(hostap, rx_rssi, rx_packets)) {
                        TASK_LOG(ERROR) << "can't get cross_rx_rssi for hostap " << hostap;
                        continue;
                    }

                    uint16_t sta_phy_tx_rate_100kb = station->cross_rx_phy_rate_100kb;
                    TASK_LOG(DEBUG) << "sta_phy_tx_rate_100kb=" << int(sta_phy_tx_rate_100kb);

                    auto radio_mac = tlvf::mac_from_string(hostap);

                    son::wireless_utils::sPhyApParams hostap_params;
                    hostap_params.is_5ghz  = hostap_is_5ghz;
                    hostap_params.bw       = hostap_bw;
                    hostap_params.ant_num  = database.get_hostap_ant_num(radio_mac);
                    hostap_params.ant_gain = database.get_hostap_ant_gain(radio_mac);
                    hostap_params.tx_power = database.get_hostap_tx_power(radio_mac);

                    current_ul_params = son::wireless_utils::estimate_ul_params(
                        rx_rssi, sta_phy_tx_rate_100kb, sta_capabilities, hostap_params.bw,
                        hostap_params.is_5ghz);
                    TASK_LOG(DEBUG)
                        << "hostap_candidate: estimated ul_tx_power=" << current_ul_params.tx_power
                        << " ul_rssi=" << int(current_ul_params.rssi);

                    dl_rssi = son::wireless_utils::estimate_dl_rssi(
                        rx_rssi, current_ul_params.tx_power, hostap_params);
                }
                hostap_phy_rate = son::wireless_utils::estimate_ap_tx_phy_rate(
                    dl_rssi, sta_capabilities, hostap_bw, hostap_is_5ghz);
                station->cross_estimated_tx_phy_rate = hostap_phy_rate; // save to DB
                double weighted_phy_rate             = calculate_weighted_phy_rate(*station);
                if (hostap == current_hostap) {
                    weighted_phy_rate *=
                        (100.0 + roaming_hysteresis_percent_bonus) / 100.0; //adds stability
                }

                TASK_LOG(DEBUG) << "calculated phy rate on bssid " << hostap << " is "
                                << weighted_phy_rate;

                if (dl_rssi <= database.config.roaming_rssi_cutoff_db) { // below cutoff
                    if (weighted_phy_rate > best_weighted_phy_rate_below_cutoff &&
                        !hostap_is_5ghz) {
                        best_weighted_phy_rate_below_cutoff = weighted_phy_rate;
                        chosen_hostap_below_cutoff          = hostap;
                    }
                } else {
                    all_hostaps_below_cutoff = false;
                    if (weighted_phy_rate > best_weighted_phy_rate) {
                        best_weighted_phy_rate = weighted_phy_rate;
                        chosen_hostap          = hostap;
                    }
                }

                LOG_CLI(
                    DEBUG,
                    "optimal_path_task:"
                        << std::endl
                        << "   hostap_candidate: channel " << hostap_channel << " mac=" << hostap
                        << ((hostap == current_hostap) ? " (current)" : " (neighbor)")
                        << "   dl_rssi=" << int(dl_rssi)
                        << (dl_rssi <= database.config.roaming_rssi_cutoff_db ? "  ** below cutoff"
                                                                              : "")
                        << std::endl
                        << "   Bandwidth=" << beerocks::utils::convert_bandwidth_to_int(hostap_bw)
                        << "   estimated_phy_rate=" << (hostap_phy_rate / (1024.0 * 1024.0))
                        << " [Mbps]"
                        << " weighted_phy_rate=" << (weighted_phy_rate / (1024.0 * 1024.0))
                        << " [Mbps]");
            } else {
                all_hostaps_below_cutoff = false;

                int8_t dl_rssi;

                if (!estimate_dl_rssi) {
                    uint8_t dl_rcpi, dl_snr;
                    if (!station->get_beacon_measurement(hostap, dl_rcpi, dl_snr)) {
                        TASK_LOG(ERROR)
                            << "get_node_beacon_measurement() failed! sta_mac: " << sta_mac
                            << ", hostap: " << hostap;
                        continue;
                    }
                    dl_rssi = wireless_utils::convert_rssi_from_rcpi(dl_rcpi);

                    TASK_LOG(DEBUG) << "bssid " << hostap << " dl_rssi: " << int(dl_rssi)
                                    << ", dl_snr:" << int(dl_snr);
                } else {
                    int8_t rx_rssi, rx_packets;
                    if (!station->get_cross_rx_rssi(hostap, rx_rssi, rx_packets)) {
                        TASK_LOG(ERROR) << "can't get cross_rx_rssi for hostap " << hostap;
                        continue;
                    }

                    uint16_t sta_phy_tx_rate_100kb = station->cross_rx_phy_rate_100kb;
                    TASK_LOG(DEBUG) << "sta_phy_tx_rate_100kb=" << int(sta_phy_tx_rate_100kb);

                    auto radio_mac = tlvf::mac_from_string(hostap);

                    son::wireless_utils::sPhyApParams hostap_params;
                    hostap_params.is_5ghz  = database.is_node_5ghz(hostap);
                    hostap_params.bw       = database.get_node_bw(hostap);
                    hostap_params.ant_num  = database.get_hostap_ant_num(radio_mac);
                    hostap_params.ant_gain = database.get_hostap_ant_gain(radio_mac);
                    hostap_params.tx_power = database.get_hostap_tx_power(radio_mac);

                    sta_capabilities =
                        database.get_station_capabilities(sta_mac, hostap_params.is_5ghz);
                    current_ul_params = son::wireless_utils::estimate_ul_params(
                        rx_rssi, sta_phy_tx_rate_100kb, sta_capabilities, hostap_params.bw,
                        hostap_params.is_5ghz);
                    TASK_LOG(DEBUG)
                        << "hostap_candidate: estimated ul_tx_power=" << current_ul_params.tx_power
                        << " ul_rssi=" << int(current_ul_params.rssi);

                    dl_rssi = son::wireless_utils::estimate_dl_rssi(
                        rx_rssi, current_ul_params.tx_power, hostap_params);
                }

                // hysteresis_bonus when below cutoff only on 2.4Ghz
                if (!(current_hostap_is_5ghz && current_below_cutoff) && hostap == current_hostap) {
                    sticky_roaming_rssi = dl_rssi;
                    int hysteresis_bonus =
                        abs(dl_rssi * (roaming_hysteresis_percent_bonus / 100.0));
                    dl_rssi += hysteresis_bonus; //adds stability
                }

                if (hostap_is_5ghz) {
                    if (dl_rssi > best_dl_rssi_5g) {
                        best_dl_rssi_5g        = dl_rssi;
                        best_dl_rssi_hostap_5g = hostap;
                    }
                } else {
                    if (dl_rssi > best_dl_rssi_2g) {
                        best_dl_rssi_2g        = dl_rssi;
                        best_dl_rssi_hostap_2g = hostap;
                    }
                }
            }
        }

        if (all_hostaps_below_cutoff && current_hostap_is_5ghz) {
            best_weighted_phy_rate = best_weighted_phy_rate_below_cutoff;
            best_dl_rssi           = best_dl_rssi_below_cutoff;
            chosen_hostap          = chosen_hostap_below_cutoff;
        }

        if (force_signal_strength_decision ||
            database.settings_client_optimal_path_roaming_prefer_signal_strength()) {
            if (best_dl_rssi_5g > best_dl_rssi_2g) {
                chosen_hostap = best_dl_rssi_hostap_5g;
                best_dl_rssi  = best_dl_rssi_5g;
            } else {
                chosen_hostap = best_dl_rssi_hostap_2g;
                best_dl_rssi  = best_dl_rssi_2g;
            }
        }

        if (chosen_hostap.empty() || (chosen_hostap == current_hostap)) {
            LOG_CLI(DEBUG, "optimal_path_task:"
                               << " could not find a better path for sta " << sta_mac << std::endl);
            database.dm_uint64_param_one_up(station->dm_path + ".MultiAPSteeringSummaryStats",
                                            "NoCandidateAPFailures");
            database.dm_uint64_param_one_up(
                "Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats",
                "NoCandidateAPFailures");
            finish();
        } else {
            chosen_bssid = database.get_hostap_vap_with_ssid(tlvf::mac_from_string(chosen_hostap),
                                                             current_hostap_ssid);
            if (!database.settings_client_optimal_path_roaming_prefer_signal_strength()) {
                // The following log print is used by the automated testing
                // Please do NOT change
                LOG_CLI(DEBUG, "optimal_path_task: Found a better optimized path for the client."
                                   << std::endl
                                   << "    best hostap for " << sta_mac << " is " << chosen_bssid
                                   << " with weighted_phy_rate="
                                   << (best_weighted_phy_rate / (1024.0 * 1024.0)) << " [Mbps]"
                                   << std::endl
                                   << "    --> steering " << sta_mac << " to " << chosen_bssid
                                   << std::endl);
            } else {
                // The following log print is used by the automated testing
                // Please do NOT change
                LOG_CLI(DEBUG, "optimal_path_task: Found a better optimized path for the client."
                                   << std::endl
                                   << "    best hostap (signal strength metric) for " << sta_mac
                                   << " is " << chosen_bssid << " with dl_rssi=" << (best_dl_rssi)
                                   << " [dBm]");
            }

            state = SEND_STEER_ACTION;
        }
        break;
    }
    case FILL_POTENTIAL_AP_LIST_CROSS: {
        if (!assert_original_parent()) {
            TASK_LOG(INFO) << sta_mac << " no longer connected to " << current_hostap_vap
                           << " aborting task";
            finish();
            return;
        }
        hostaps.clear();

        auto sta_bridge = database.get_node_parent(current_hostap);
        if (!database.settings_client_optimal_path_roaming()) {
            state = REQUEST_CROSS_RSSI_MEASUREMENTS;
            break;
        }
        //build pending mac list //
        auto agents  = database.get_all_connected_agents();
        auto subtree = database.get_node_subtree(sta_mac);

        std::vector<std::shared_ptr<Agent>> agents_outside_subtree;

        // insert all ires that outside the subtree to "agents_outside_subtree",
        // because it is impossible to move ire to a child ire. station doesn't has subtree.
        std::copy_if(agents.begin(), agents.end(), std::back_inserter(agents_outside_subtree),
                     [&](std::shared_ptr<Agent> agent) {
                         return (subtree.find(tlvf::mac_to_string(agent->al_mac)) == subtree.end());
                     });

        auto channel = database.get_node_channel(sta_mac);

        //searching for sub band hostap /backhaul(client) measurement match for each ire
        for (auto &agent : agents_outside_subtree) {
            bool found_band_match = false;
            std::string hostap_backhaul_manager =
                tlvf::mac_to_string(agent->backhaul.wireless_backhaul_radio->radio_uid);
            std::string hostap_backhaul;
            if (tlvf::mac_from_string(sta_bridge) == agent->al_mac) {
                continue;
            }
            //searching for hostap 5Ghz Low/High direct match ,2.4Ghz auto picked when sta is 2.4
            for (const auto &radio_map_element : agent->radios) {
                auto radio         = radio_map_element.second;
                auto hostap        = tlvf::mac_to_string(radio->radio_uid);
                hostap_backhaul    = database.get_node_parent_backhaul(hostap);
                int hostap_channel = database.get_node_channel(hostap);
                if (database.is_ap_out_of_band(hostap, sta_mac) ||
                    (!database.is_hostap_active(tlvf::mac_from_string(hostap))) ||
                    is_hostap_on_cs_process(hostap)) {
                    TASK_LOG(DEBUG) << "continue " << hostap;
                    continue;
                }
                bool hostap_meas = ((!database.get_node_5ghz_support(hostap)) ||
                                    (wireless_utils::which_subband(channel)) ==
                                        (wireless_utils::which_subband(hostap_channel)));
                if (hostap_meas) {
                    TASK_LOG(DEBUG) << "sub band match insert to list, hostap  = " << hostap;
                    hostaps.insert(hostap);
                    found_band_match = true;
                    break;
                }
            }

            //when there is no 5Ghz hostap and backhaul direct Low/High match, searching for hostap Low/High support match
            if (!found_band_match && database.settings_front_measurements()) {
                if (database.is_node_wireless(hostap_backhaul) &&
                    (database.get_node_type(hostap_backhaul) != beerocks::TYPE_GW) &&
                    database.is_node_5ghz(sta_mac)) {
                    auto backhaul_channel = database.get_node_channel(hostap_backhaul);
                    auto hostap_meas      = ((wireless_utils::which_subband(channel)) ==
                                        (wireless_utils::which_subband(backhaul_channel)));
                    if (hostap_meas) {
                        TASK_LOG(DEBUG)
                            << "sub band match insert to list, hostap_backhaul_manager = "
                            << hostap_backhaul_manager;
                        hostaps.insert(hostap_backhaul_manager);
                        found_band_match = true;
                        continue;
                    }
                }
            }
            //when there is no 5Ghz hostap and backhaul Low/High match searching for
            if (!found_band_match) {
                for (const auto &radio_map_element : agent->radios) {
                    auto radio  = radio_map_element.second;
                    auto hostap = tlvf::mac_to_string(radio->radio_uid);
                    if (hostap == current_hostap || database.is_ap_out_of_band(hostap, sta_mac) ||
                        (!database.is_hostap_active(tlvf::mac_from_string(hostap)))) {
                        continue;
                    }
                    if (database.capability_check(hostap, channel)) {
                        TASK_LOG(DEBUG)
                            << "sub band support match insert to list, hostap = " << hostap;
                        hostaps.insert(hostap);
                        found_band_match = true;
                        break;
                    }
                }
            }
        }

        state = REQUEST_CROSS_RSSI_MEASUREMENTS;
        break;
    }
    case REQUEST_CROSS_RSSI_MEASUREMENTS: {
        if (!assert_original_parent()) {
            TASK_LOG(INFO) << sta_mac << " no longer connected to " << current_hostap_vap
                           << " aborting task";
            finish();
            return;
        }

        // send req to sta hostap //
        auto agent_mac = database.get_node_parent_ire(current_hostap);
        auto request   = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>(cmdu_tx, id);
        if (request == nullptr) {
            LOG(ERROR)
                << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST message!";
            finish();
            break;
        }

        request->params().mac  = tlvf::mac_from_string(sta_mac);
        request->params().ipv4 = network_utils::ipv4_from_string(database.get_node_ipv4(sta_mac));
        request->params().channel   = database.get_node_channel(current_hostap);
        request->params().bandwidth = database.get_node_bw(current_hostap);
        request->params().cross     = hostaps.empty() ? 0 : 1;
        request->params().mon_ping_burst_pkt_num =
            database.get_measurement_window_size(current_hostap);
        request->params().measurement_delay = database.get_measurement_delay(current_hostap);
        //set ap associated ire timestamp
        database.set_measurement_sent_timestamp(current_hostap);

        son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database, current_hostap);
        add_pending_mac(current_hostap,
                        beerocks_message::ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE);
        if (request->params().cross) {
            add_pending_mac(
                current_hostap,
                beerocks_message::ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION);
        }
        TASK_LOG(DEBUG) << "requesting rssi measurements for " << sta_mac << " from "
                        << current_hostap;

        set_responses_timeout(RX_RSSI_MEASUREMENT_REQUEST_TIMEOUT_MSEC);

        state = FIND_AND_PICK_HOSTAP_CROSS;
        break;
    }

    case FIND_AND_PICK_HOSTAP_CROSS: {
        if (!assert_original_parent()) {
            TASK_LOG(INFO) << sta_mac << " no longer connected to " << current_hostap_vap
                           << " aborting task";
            finish();
            return;
        }

        if (!hostaps.empty()) //no cross measurement
        {
            TASK_LOG(DEBUG) << " **after all responses has been received calculating delays** ";
            auto temp_cross_hostaps = hostaps;
            if (!calculate_measurement_delay(temp_cross_hostaps, current_hostap, sta_mac)) {
                TASK_LOG(DEBUG)
                    << " **re-measure cross ire STATE = REQUEST_CROSS_RSSI_MEASUREMENTS:** ";
                state = REQUEST_CROSS_RSSI_MEASUREMENTS;
                break;
            }
            TASK_LOG(DEBUG) << "burst_window_size "
                            << int(database.get_measurement_window_size(current_hostap))
                            << " calculate_measurement_delay_count = "
                            << int(calculate_measurement_delay_count);
            calculate_measurement_delay_count = 0;
        }

        // The following log print is used by the automated testing
        // Please do NOT change
        TASK_LOG(DEBUG) << "Finished gathering cross rssi measurements";
        TASK_LOG(DEBUG) << "calculating estimate hostap dl rssi/rate for sta " << sta_mac;

        //get sta parameters
        uint16_t sta_phy_tx_rate_100kb = station->cross_rx_phy_rate_100kb;
        TASK_LOG(DEBUG) << "sta_phy_tx_rate_100kb=" << int(sta_phy_tx_rate_100kb);
        //build candidate hostap list
        std::vector<std::pair<std::string, bool>> hostap_candidates;
        //add current ap
        hostap_candidates.push_back({current_hostap, false});

        if (database.settings_client_band_steering()) {
            auto hostap_siblings = database.get_node_siblings(current_hostap);
            for (auto sibling : hostap_siblings) {
                if (!database.is_hostap_active(tlvf::mac_from_string(sibling)) ||
                    is_hostap_on_cs_process(sibling)) {
                    TASK_LOG(DEBUG) << "continue " << sibling;
                    continue;
                }
                hostap_candidates.push_back({sibling, true});
            }
        }

        //add all other ap's
        for (auto &hostap : hostaps) {
            if (hostap == current_hostap)
                continue;

            auto agent = database.get_agent_by_radio_uid(tlvf::mac_from_string(hostap));
            if (!agent) {
                TASK_LOG(ERROR) << "agent containing radio " << hostap << " not found";
                continue;
            }

            bool is_backhaul_manager = (agent->backhaul.wireless_backhaul_radio->radio_uid ==
                                        tlvf::mac_from_string(hostap));

            //when hostap is backhaul manager , the mathing candidate is his same band sibling
            if (is_backhaul_manager &&
                database.get_node_type(database.get_node_parent(hostap)) != beerocks::TYPE_GW) {
                auto sibling_backhaul_manager = database.get_node_siblings(hostap);
                for (auto &sibling : sibling_backhaul_manager) {
                    if (!database.is_ap_out_of_band(sibling, sta_mac)) {
                        //actual ap candidate (is case measured through backhaul)
                        hostap_candidates.push_back({sibling, false});
                    } else {
                        //adding the backhaul_manager band_steering candidate
                        if (database.settings_client_band_steering()) {
                            //band steering candidate
                            if (database.is_hostap_active(tlvf::mac_from_string(sibling)) ||
                                !is_hostap_on_cs_process(sibling)) {
                                hostap_candidates.push_back({sibling, true});
                            } else {
                                TASK_LOG(DEBUG) << "continue " << sibling;
                            }
                        }
                    }
                }
            } else {
                hostap_candidates.push_back({hostap, false});
                if (database.settings_client_band_steering()) {
                    auto hostap_siblings = database.get_node_siblings(hostap);
                    for (auto &sibling : hostap_siblings) {
                        if (!database.is_hostap_active(tlvf::mac_from_string(sibling)) ||
                            is_hostap_on_cs_process(sibling)) {
                            TASK_LOG(DEBUG) << "continue " << sibling;
                            continue;
                        }
                        hostap_candidates.push_back({sibling, true});
                    }
                }
            }
        }

        // Check if hostap has suitable ssid
        auto it = hostap_candidates.begin();
        while (it != hostap_candidates.end()) {
            std::string candidate_bssid = database.get_hostap_vap_with_ssid(
                tlvf::mac_from_string(it->first), current_hostap_ssid);

            if (candidate_bssid.empty()) {
                LOG(INFO) << "Remove candidate " << it->first
                          << ". Hostap doesn't have current_hostap_ssid " << current_hostap_ssid;
                it = hostap_candidates.erase(it);
                continue;
            }

            // Steering allowed on all vaps unless load_steer_on_vaps list is defined
            // on the platform, in that case, verify that vap is on that list.
            if (!database.is_vap_on_steer_list(tlvf::mac_from_string(candidate_bssid))) {
                TASK_LOG(INFO) << "Remove candidate " << it->first << " , vap " << candidate_bssid
                               << " is not in steer list: " << database.config.load_steer_on_vaps;
                it = hostap_candidates.erase(it);
            } else {
                ++it;
            }
        }

        // Check client's steering persistent database for any band/radio/device restrictions.
        // This code is duplicated for both FIND_AND_PICK_HOSTAP_CROSS FIND_AND_PICK_HOSTAP_11K
        // TODO: Need to create preliminary state that prepares candidate radio list
        // regardless of client's 11k support #PPM-102.
        auto client = tlvf::mac_from_string(sta_mac);
        if (station->stay_on_initial_radio == eTriStateBool::TRUE) {
            TASK_LOG(INFO) << "Client stay on initial radio enabled";
            auto client_initial_radio = station->initial_radio;

            if (client_initial_radio == tlvf::mac_from_string(current_hostap)) {
                TASK_LOG(INFO) << "Client is already on initial radio " << client_initial_radio;
                finish();
                break;
            }
            // Client is not on initial radio, let's try to find it on the steering potential candidate list.
            auto hostap_it =
                std::find_if(hostap_candidates.begin(), hostap_candidates.end(),
                             [&](const std::pair<std::string, bool> &hostap) {
                                 return hostap.first == tlvf::mac_to_string(client_initial_radio);
                             });

            if (hostap_it != hostap_candidates.end()) {
                // Initial client radio is on the candidate list, force steer the client there.
                chosen_bssid = database.get_hostap_vap_with_ssid(
                    tlvf::mac_from_string(hostap_it->first), current_hostap_ssid);
                state          = SEND_STEER_ACTION;
                is_force_steer = true;
                chosen_method.append("Steer client imminently to initial radio " +
                                     hostap_it->first + " ");
                // The following log print is used by the automated testing
                // Please do NOT change
                TASK_LOG(INFO) << "Resolving Optimal task on persistent preference: "
                               << chosen_method;
                break;
            }
            TASK_LOG(WARNING) << "Client's initial radio " << client_initial_radio
                              << " is not on the candidate ap list, continue as usual.";
        }

        auto selected_bands = station->selected_bands;
        if ((selected_bands != PARAMETER_NOT_CONFIGURED) &&
            (selected_bands != eClientSelectedBands::eSelectedBands_Disabled)) {
            TASK_LOG(INFO) << "Client stay on selected bands enabled";
            if (!database.is_hostap_on_client_selected_bands(
                    client, tlvf::mac_from_string(current_hostap))) {
                TASK_LOG(INFO) << "Current radio " << current_hostap
                               << " is not on one of client's selected bands "
                               << int(station->selected_bands);
                // Try to find radio with selected bands first on local device (same device the client
                // is currently connected on) and force steer the client to that radio.
                auto current_hostap_siblings = database.get_node_siblings(current_hostap);
                auto sibling_it =
                    std::find_if(current_hostap_siblings.begin(), current_hostap_siblings.end(),
                                 [&](const std::string &sibling) {
                                     return database.is_hostap_on_client_selected_bands(
                                         client, tlvf::mac_from_string(sibling));
                                 });

                if (sibling_it != current_hostap_siblings.end()) {
                    chosen_bssid = database.get_hostap_vap_with_ssid(
                        tlvf::mac_from_string(sibling_it->data()), current_hostap_ssid);
                    state          = SEND_STEER_ACTION;
                    is_force_steer = true;
                    chosen_method.append("Found local radio " + std::string(sibling_it->data()) +
                                         " on selected bands, force steer client to that radio ");

                    // The following log print is used by the automated testing
                    // Please do NOT change
                    TASK_LOG(INFO)
                        << "Resolving Optimal task on persistent preference: " << chosen_method;
                    break;
                }
                TASK_LOG(WARNING) << "Couldnt find local radio on selected bands "
                                  << int(station->selected_bands) << " with same client's ssid "
                                  << current_hostap_ssid;
            }
            // In case client is already connected to one of the selected bands
            // continue with optimal path task but remove all non selected band hostaps
            // from steering candidate list.
            remove_all_client_non_selected_band_radios(hostap_candidates, client);
        }

        // hostap's list is ready , lets check if we have candidates left
        const auto hostap_candidates_size = hostap_candidates.size();
        if (hostap_candidates_size == 0) {
            TASK_LOG(WARNING) << "Candidates list is empty, aborting optimal path task";
            database.dm_uint64_param_one_up(station->dm_path + ".MultiAPSteeringSummaryStats",
                                            "NoCandidateAPFailures");
            database.dm_uint64_param_one_up(
                "Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats",
                "NoCandidateAPFailures");
            finish();
            break;
        }

        if ((hostap_candidates_size == 1) && (hostap_candidates.begin()->first == current_hostap)) {
            TASK_LOG(DEBUG)
                << "Current hostap " << current_hostap
                << "is the only steering candidate left on the list, aborting optimal path task";
            database.dm_uint64_param_one_up(station->dm_path + ".MultiAPSteeringSummaryStats",
                                            "NoCandidateAPFailures");
            database.dm_uint64_param_one_up(
                "Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats",
                "NoCandidateAPFailures");
            finish();
            break;
        }

        //calculate tx phy rate and find best_weighted_phy_rate
        int roaming_hysteresis_percent_bonus = database.config.roaming_hysteresis_percent_bonus;
        son::wireless_utils::sPhyApParams hostap_params;
        son::wireless_utils::sPhyUlParams current_ul_params;
        const beerocks::message::sRadioCapabilities *sta_capabilities;
        beerocks::message::sRadioCapabilities default_sta_cap;
        int ul_rssi           = beerocks::RSSI_INVALID;
        int estimated_ul_rssi = beerocks::RSSI_INVALID;
        int estimated_dl_rssi = beerocks::RSSI_INVALID;
        double hostap_phy_rate;
        double best_weighted_phy_rate              = 0;
        double best_weighted_phy_rate_below_cutoff = 0;
        int best_ul_rssi_5g                        = beerocks::RSSI_MIN;
        int best_ul_rssi_2g                        = beerocks::RSSI_MIN;
        std::string best_ul_rssi_hostap_5g;
        std::string best_ul_rssi_hostap_2g;
        int best_ul_rssi              = beerocks::RSSI_INVALID;
        bool current_hostap_is_5ghz   = database.is_node_5ghz(current_hostap);
        bool all_hostaps_below_cutoff = true;
        std::string chosen_hostap_below_cutoff;
        sticky_roaming_rssi = 0;

        // hostap's in this list are in order, current_hostap is first
        for (auto it : hostap_candidates) {
            auto hostap         = it.first;
            auto hostap_sibling = it.second;

            auto radio_mac = tlvf::mac_from_string(hostap);

            int hostap_channel    = database.get_node_channel(hostap);
            auto skip_estimation  = false; // initialise for each HostAP candidate
            hostap_params.is_5ghz = database.is_node_5ghz(hostap);

            if ((hostap_params.is_5ghz && !database.get_node_5ghz_support(sta_mac)) ||
                (!hostap_params.is_5ghz && !database.get_node_24ghz_support(sta_mac))) {
                TASK_LOG(DEBUG) << "AP candidate and STA must support same band | SKIP " << hostap;
                continue;
            }

            // Get STA capabilities
            TASK_LOG(DEBUG) << "getting capabilities for sta_mac " << sta_mac << " on band "
                            << (hostap_params.is_5ghz ? "5GHz" : "2.4GHz");
            sta_capabilities = database.get_station_capabilities(sta_mac, hostap_params.is_5ghz);
            if (sta_capabilities == nullptr) {
                TASK_LOG(WARNING) << "STA capabilities are empty - use default capabilities";
                get_station_default_capabilities(hostap_params.is_5ghz, default_sta_cap);
                sta_capabilities = &default_sta_cap;
            }

            TASK_LOG(DEBUG) << "sta_capabilities:"
                            << " ht_ss=" << int(sta_capabilities->ht_ss)
                            << " ht_mcs=" << int(sta_capabilities->ht_mcs)
                            << " vht_ss=" << int(sta_capabilities->vht_ss)
                            << " vht_mcs=" << int(sta_capabilities->vht_mcs)
                            << " ant_num=" << int(sta_capabilities->ant_num)
                            << " ht_bw=" << int(sta_capabilities->ht_bw)
                            << " vht_bw=" << int(sta_capabilities->vht_bw);

            hostap_params.bw       = database.get_node_bw(hostap);
            hostap_params.ant_num  = database.get_hostap_ant_num(radio_mac);
            hostap_params.ant_gain = database.get_hostap_ant_gain(radio_mac);
            hostap_params.tx_power = database.get_hostap_tx_power(radio_mac);

            if (!hostap_sibling) {
                int8_t rx_rssi, rx_packets;
                if (!station->get_cross_rx_rssi(hostap, rx_rssi, rx_packets)) {
                    TASK_LOG(ERROR) << "can't get cross_rx_rssi for hostap " << hostap;
                    continue;
                } else {
                    TASK_LOG(DEBUG) << "hostap: " << hostap << ", rx_rssi=" << int(rx_rssi)
                                    << ", rx_packets=" << int(rx_packets);
                }

                if (rx_packets < 0) {
                    TASK_LOG(DEBUG)
                        << "hostap is busy (rx_packets=" << int(rx_packets) << "), restart task;";
                    //FIXME TODO --> need to restart task
                }

                ul_rssi = rx_rssi;

                // calc ul rssi for current ap
                if (hostap == current_hostap) {
                    sticky_roaming_rssi = rx_rssi;
                    current_ul_params   = son::wireless_utils::estimate_ul_params(
                        ul_rssi, sta_phy_tx_rate_100kb, sta_capabilities, hostap_params.bw,
                        hostap_params.is_5ghz);

                    skip_estimation = true; // indicate estimation is done and can be skipped later

                    TASK_LOG(DEBUG)
                        << "hostap_candidate: estimated ul_tx_power=" << current_ul_params.tx_power
                        << " ul_rssi=" << int(current_ul_params.rssi);
                } else if (database.config.roaming_unconnected_client_rssi_compensation_db != 0) {
                    // add compensation for an AP who is not on the same IRE as the client
                    ul_rssi += database.config.roaming_unconnected_client_rssi_compensation_db;
                    TASK_LOG(DEBUG)
                        << "hostap_candidate: add roaming_unconnected_sta_rssi_compensation of "
                        << database.config.roaming_unconnected_client_rssi_compensation_db << " db";
                }
            }

            if (ul_rssi == beerocks::RSSI_INVALID) {
                TASK_LOG(ERROR) << "ul_rssi for hostap " << hostap << " is invalid, skip it!";
                continue;
            }

            if (hostap_params.is_5ghz != current_hostap_is_5ghz) { // cross band estimation
                if (current_hostap_is_5ghz) {
                    estimated_ul_rssi = ul_rssi + database.config.roaming_band_pathloss_delta_db;
                } else {
                    estimated_ul_rssi = ul_rssi - database.config.roaming_band_pathloss_delta_db;
                }
            } else {
                estimated_ul_rssi = ul_rssi;
            }

            // 1. Estimate UL parameters if not yet done
            if (!skip_estimation) {
                current_ul_params = son::wireless_utils::estimate_ul_params(
                    ul_rssi, sta_phy_tx_rate_100kb, sta_capabilities, hostap_params.bw,
                    hostap_params.is_5ghz);
            }

            // Check if estimated UL phyrate is below table range and switch to
            // signal-strength-estimation if allowed. Otherwise continue with phyrate estimation.
            if (!database.settings_client_optimal_path_roaming_prefer_signal_strength() &&
                (current_ul_params.status == son::wireless_utils::ESTIMATION_SUCCESS)) {

                TASK_LOG(DEBUG) << "Stay with phyrate-estimation method";

                // 2. Estimate DL RSSI
                estimated_dl_rssi = son::wireless_utils::estimate_dl_rssi(
                    estimated_ul_rssi, current_ul_params.tx_power, hostap_params);

                // 3. Estimate AP TX PHY RATE
                hostap_phy_rate = son::wireless_utils::estimate_ap_tx_phy_rate(
                    estimated_dl_rssi, sta_capabilities, hostap_params.bw, hostap_params.is_5ghz);

                station->cross_estimated_tx_phy_rate = hostap_phy_rate;

                // 4. Calculate weighed PHY RATE
                double weighted_phy_rate = calculate_weighted_phy_rate(*station);

                if (hostap == current_hostap) {
                    weighted_phy_rate *=
                        (100.0 + roaming_hysteresis_percent_bonus) / 100.0; //adds stability
                }

                if ((estimated_ul_rssi <= database.config.roaming_rssi_cutoff_db) || // below cutoff
                    (estimated_dl_rssi <= database.config.roaming_rssi_cutoff_db)) {
                    if (weighted_phy_rate > best_weighted_phy_rate_below_cutoff &&
                        !hostap_params.is_5ghz) {
                        best_weighted_phy_rate_below_cutoff = weighted_phy_rate;
                        chosen_hostap_below_cutoff          = hostap;
                    }
                } else {
                    all_hostaps_below_cutoff = false;
                    if (weighted_phy_rate > best_weighted_phy_rate) {
                        best_weighted_phy_rate = weighted_phy_rate;
                        chosen_hostap          = hostap;
                    }
                }

                LOG_CLI(DEBUG,
                        "optimal_path_task:"
                            << std::endl
                            << "   hostap_candidate: channel " << hostap_channel
                            << " mac=" << hostap
                            << ((hostap == current_hostap) ? " (current) | " : " (neighbor) | ")
                            << std::endl
                            << (ul_rssi == estimated_ul_rssi ? "    ul_rssi="
                                                             : "    estimated_ul_rssi=")
                            << estimated_ul_rssi
                            << (estimated_ul_rssi <= database.config.roaming_rssi_cutoff_db
                                    ? "  ** below cutoff"
                                    : "")
                            << std::endl
                            << "    estimated_dl_rssi=" << int(estimated_dl_rssi)
                            << (estimated_dl_rssi <= database.config.roaming_rssi_cutoff_db
                                    ? "  ** below cutoff"
                                    : "")
                            << std::endl
                            << "Bandwidth=" << utils::convert_bandwidth_to_int(hostap_params.bw)
                            << std::endl
                            << "    estimated_phy_rate=" << (hostap_phy_rate / (1024.0 * 1024.0))
                            << " [Mbps]"
                            << " weighted_phy_rate=" << (weighted_phy_rate / (1024.0 * 1024.0))
                            << " [Mbps]");
            } else if (current_ul_params.status ==
                       son::wireless_utils::ESTIMATION_FAILURE_BELOW_RANGE) {
                TASK_LOG(DEBUG) << "Switch to signal-strength-estimation method";

                all_hostaps_below_cutoff = false;
                if (hostap == current_hostap) {
                    int hysteresis_bonus =
                        abs(estimated_ul_rssi * (roaming_hysteresis_percent_bonus / 100.0));
                    estimated_ul_rssi += hysteresis_bonus; //adds stability
                }

                if (hostap_params.is_5ghz) {
                    if (estimated_ul_rssi > best_ul_rssi_5g) {
                        best_ul_rssi_5g        = estimated_ul_rssi;
                        best_ul_rssi_hostap_5g = hostap;
                    }
                } else {
                    if (estimated_ul_rssi > best_ul_rssi_2g) {
                        best_ul_rssi_2g        = estimated_ul_rssi;
                        best_ul_rssi_hostap_2g = hostap;
                    }
                }
                LOG_CLI(DEBUG, "optimal_path_task:"
                                   << std::endl
                                   << "   hostap_candidate: channel " << hostap_channel
                                   << " mac=" << hostap
                                   << ((hostap == current_hostap) ? " (current)" : " (neighbor)")
                                   << std::endl
                                   << (ul_rssi == estimated_ul_rssi ? "    ul_rssi="
                                                                    : "    estimated_ul_rssi=")
                                   << estimated_ul_rssi
                                   << (estimated_ul_rssi <= database.config.roaming_rssi_cutoff_db
                                           ? "  ** below cutoff"
                                           : ""));
            } else {
                continue; // in case of estimation returns ESTIMATION_FAILURE_INVALID_RSSI
            }
        }

        TASK_LOG(DEBUG) << "end of hostap candidate list";

        if (all_hostaps_below_cutoff && current_hostap_is_5ghz) {
            best_weighted_phy_rate = best_weighted_phy_rate_below_cutoff;
            chosen_hostap          = chosen_hostap_below_cutoff;
        }

        if (database.settings_client_optimal_path_roaming_prefer_signal_strength()) {
            // Select 5GHz HostAP in case UL RSSI towards it is above cutoff
            if (best_ul_rssi_5g > database.config.roaming_rssi_cutoff_db) {
                chosen_hostap = best_ul_rssi_hostap_5g;
                best_ul_rssi  = best_ul_rssi_5g;
            } else {
                // In any other case select 2.4GHz HostAP
                chosen_hostap = best_ul_rssi_hostap_2g;
                best_ul_rssi  = best_ul_rssi_2g;
                LOG_CLI(DEBUG,
                        "Change selected HostAP to 2.4GHz band as 5GHz band is below cutoff"
                            << " | Roaming RSSI cutoff:" << database.config.roaming_rssi_cutoff_db
                            << " | 5GHz best UL RSSI:" << best_ul_rssi_5g
                            << " | 2.4GHz best UL RSSI:" << best_ul_rssi_2g);
            }
        }

        chosen_bssid = database.get_hostap_vap_with_ssid(tlvf::mac_from_string(chosen_hostap),
                                                         current_hostap_ssid);

        if (chosen_hostap.empty() || (chosen_hostap == current_hostap) || chosen_bssid.empty()) {
            LOG_CLI(DEBUG, "optimal_path_task:" << std::endl
                                                << "   could not find a better path for sta "
                                                << sta_mac << std::endl);
            database.dm_uint64_param_one_up(station->dm_path + ".MultiAPSteeringSummaryStats",
                                            "NoCandidateAPFailures");
            database.dm_uint64_param_one_up(
                "Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats",
                "NoCandidateAPFailures");
            finish();
        } else {
            if (!database.settings_client_optimal_path_roaming_prefer_signal_strength()) {
                chosen_method.append(" PHY rate ");
                // The following log print is used by the automated testing
                // Please do NOT change
                LOG_CLI(DEBUG, "optimal_path_task: Found a better optimized path for the client."
                                   << std::endl
                                   << "    best hostap for " << sta_mac << " is " << chosen_bssid
                                   << " with weighted_phy_rate="
                                   << (best_weighted_phy_rate / (1024.0 * 1024.0)) << " [Mbps]"
                                   << std::endl
                                   << "    --> steering " << sta_mac << " to " << chosen_bssid
                                   << std::endl);
            } else {
                chosen_method.append(" link quality (RSSI) ");
                // The following log print is used by the automated testing
                // Please do NOT change
                LOG_CLI(DEBUG, "optimal_path_task: Found a better optimized path for the client."
                                   << std::endl
                                   << "    best hostap (signal strength metric) for " << sta_mac
                                   << " is " << chosen_bssid << " with ul_rssi=" << (best_ul_rssi)
                                   << " [dBm]" << std::endl
                                   << "    --> steering " << sta_mac << " to " << chosen_bssid
                                   << std::endl);
            }
            state = SEND_STEER_ACTION;
        }
        break;
    }
    case SEND_STEER_ACTION: {

        state                = WAIT_FOR_HANDOVER;
        int steering_task_id = 0;

        std::string method = " 11v (BTM) ";
        if (!database.get_node_11v_capability(*station)) {
            method = std::string(" Legacy ");
        }

        if (is_force_steer) {
            chosen_method.append(" [forced steering] ");
        }
        chosen_method.append(" [optimal_path_task] ");
        if (database.get_node_11v_capability(*station) && !is_force_steer) {
            if (sticky_roaming_rssi <= database.config.roaming_sticky_client_rssi_threshold) {
                TASK_LOG(DEBUG) << "optimal_path_task: steering with disassociate imminent, sta "
                                << sta_mac << " steer from BSSID " << current_hostap_vap
                                << " to BSSID " << chosen_bssid;
                bool disassoc_imminent = true;
                method.append(" [with imminent] ");
                steering_task_id =
                    son_actions::steer_sta(database, cmdu_tx, tasks, sta_mac, chosen_bssid,
                                           chosen_method, method, disassoc_imminent);
            } else {
                TASK_LOG(DEBUG) << "optimal_path_task: steering without disassociate imminent, sta "
                                << sta_mac << " steer from BSSID " << current_hostap_vap
                                << " to BSSID " << chosen_bssid;
                bool disassoc_imminent = false;
                steering_task_id =
                    son_actions::steer_sta(database, cmdu_tx, tasks, sta_mac, chosen_bssid,
                                           chosen_method, method, disassoc_imminent);
            }
        } else if (database.settings_legacy_client_roaming()) {
            TASK_LOG(DEBUG) << "optimal_path_task: steering with disassociate imminent, sta "
                            << sta_mac << " steer from BSSID " << current_hostap_vap << " to BSSID "
                            << chosen_bssid;
            bool disassoc_imminent = true;
            method.append(" [imminent] ");
            steering_task_id =
                son_actions::steer_sta(database, cmdu_tx, tasks, sta_mac, chosen_bssid,
                                       chosen_method, method, disassoc_imminent);
        }

        wait_for_task_end(steering_task_id, 30000);

        break;
    }
    case WAIT_FOR_HANDOVER: {
        /*
             * task should die before actually reaching this state
             * unless steering fails for some reason
             */
        LOG_CLI(DEBUG,
                "optimal_path_task: steering for " << sta_mac << " timed out, finishing task");
        finish();
        break;
    }
    default:
        break;
    }
}

bool optimal_path_task::check_if_sta_can_steer_to_ap(const std::string &ap_mac)
{
    bool hostap_is_5ghz = database.is_node_5ghz(ap_mac);
    bool sta_is_5ghz    = database.is_node_5ghz(sta_mac);

    if ((hostap_is_5ghz && !database.get_node_5ghz_support(sta_mac)) ||
        (!hostap_is_5ghz && !database.get_node_24ghz_support(sta_mac)) ||
        (!database.settings_client_band_steering() && (sta_is_5ghz != hostap_is_5ghz))) {
        TASK_LOG(DEBUG) << "sta " << sta_mac << " cannot steer to hostap " << ap_mac << std::endl
                        << "  hostap_is_5ghz = " << hostap_is_5ghz << std::endl
                        << "  sta_is_5ghz = " << sta_is_5ghz << std::endl
                        << "  node_5ghz_support = " << database.get_node_5ghz_support(sta_mac)
                        << std::endl
                        << "  node_24ghz_support = " << database.get_node_24ghz_support(sta_mac)
                        << std::endl
                        << "  client_band_steering = " << database.settings_client_band_steering();
        return false;
    }
    return true;
}

void optimal_path_task::send_rssi_measurement_request(const sMacAddr &agent_mac,
                                                      const std::string &client_mac, int channel,
                                                      const std::string &hostap, int id)
{
    auto hostap_mac = database.get_node_parent(client_mac);
    auto request    = message_com::create_vs_message<
        beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>(cmdu_tx, id);
    if (request == nullptr) {
        LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST message!";
        return;
    }
    database.get_node_parent_backhaul(hostap);
    request->params().mac                    = tlvf::mac_from_string(client_mac);
    request->params().ipv4                   = network_utils::ipv4_from_string("0.0.0.0");
    request->params().cross                  = 1;
    request->params().channel                = channel;
    request->params().bandwidth              = database.get_node_bw(hostap_mac);
    request->params().mon_ping_burst_pkt_num = database.get_measurement_window_size(current_hostap);
    request->params().vht_center_frequency =
        database.get_hostap_vht_center_frequency(tlvf::mac_from_string(hostap_mac));
    TASK_LOG(DEBUG) << "vht_center_frequency = " << int(request->params().vht_center_frequency);
    //taking measurement request time stamp
    database.set_measurement_sent_timestamp(hostap);
    //sending delay parameter to measurement request
    request->params().measurement_delay = database.get_measurement_delay(hostap);

    son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database, hostap);

    add_pending_mac(hostap, beerocks_message::ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE);
    TASK_LOG(DEBUG) << "sending cross rx_rssi measurement request to " << hostap
                    << " for sta=" << client_mac << " channel=" << channel;
    return;
}

void optimal_path_task::handle_responses_timeout(
    std::unordered_multimap<std::string, beerocks_message::eActionOp_CONTROL> timed_out_macs)
{
    for (auto entry : timed_out_macs) {
        std::string mac = entry.first;
        TASK_LOG(DEBUG) << "response from " << mac << " timed out";
        if (state >= FILL_POTENTIAL_AP_LIST_CROSS && state <= FIND_AND_PICK_HOSTAP_CROSS) {
            hostaps.erase(mac); //hostaps that didn't respond on time won't be considered as active
        }
    }
}

void optimal_path_task::handle_response(std::string mac,
                                        std::shared_ptr<beerocks_header> beerocks_header)
{

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION: {
        auto notification = beerocks_header->getClass<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION>();

        if (!notification) {
            TASK_LOG(ERROR) << "getClass failed for "
                               "cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION";
            return;
        }

        std::string client_mac = tlvf::mac_to_string(notification->mac());
        std::string hostap_mac = mac;
        int channel            = database.get_node_channel(client_mac);

        TASK_LOG(DEBUG) << "optimal_path - handle_response ";
        for (auto &hostap : hostaps) {
            TASK_LOG(DEBUG) << "hostap = " << hostap;
        }

        LOG_CLI(DEBUG, "ACTION_CONTROL_CLIENT_MEASUREMENT_START connected AP, client_mac="
                           << client_mac << " received from hostap " << hostap_mac
                           << " channel=" << channel);

        for (auto &hostap : hostaps) {
            auto agent_mac = database.get_node_parent_ire(hostap);
            send_rssi_measurement_request(agent_mac, client_mac, channel, hostap, id);
        }

        break;
    }
    case beerocks_message::ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE: {
        break;
    }
    case beerocks_message::ACTION_CONTROL_CLIENT_BEACON_11K_RESPONSE: {
        auto response =
            beerocks_header
                ->getClass<beerocks_message::cACTION_CONTROL_CLIENT_BEACON_11K_RESPONSE>();

        if (!response) {
            TASK_LOG(ERROR) << "getClass failed for ACTION_CONTROL_CLIENT_BEACON_11K_RESPONSE";
            return;
        }

        auto bssid     = tlvf::mac_to_string(response->params().bssid);
        auto radio_mac = database.get_node_parent_radio(bssid);
        TASK_LOG(INFO) << "response for beacon measurement request was received on bssid " << bssid;
        if (potential_11k_aps.find(radio_mac) == potential_11k_aps.end()) {
            TASK_LOG(WARNING) << "unexpected measurement on bssid " << bssid;
            break;
        }

        if (son_actions::validate_beacon_measurement_report(response->params(), sta_mac, bssid)) {
            auto station = database.get_station(tlvf::mac_from_string(sta_mac));
            if (!station) {
                TASK_LOG(ERROR) << "station " << sta_mac << " not found";
                break;
            }

            potential_11k_aps[radio_mac] = true;
            station->set_beacon_measurement(radio_mac, response->params().rcpi,
                                            response->params().rsni);
            valid_beacon_measurement_report_count++;
            TASK_LOG(INFO) << "beacon measurement response on bssid " << bssid << " is valid!";
            if (valid_beacon_measurement_report_count == potential_11k_aps.size()) {
                state = FIND_AND_PICK_HOSTAP_11K;
            }
        } else {
            TASK_LOG(INFO) << "beacon measurement response on bssid " << bssid << " is invalid!";
        }
        break;
    }
    default: {
        TASK_LOG(ERROR) << "Unsupported action_op:" << int(beerocks_header->action_op());
        break;
    }
    }
}

bool optimal_path_task::assert_original_parent()
{
    if (database.get_node_parent(sta_mac) != current_hostap_vap ||
        database.get_node_state(sta_mac) != beerocks::STATE_CONNECTED) {
        TASK_LOG(DEBUG) << "client disconnected from original parent, task is irrelevant";
        return false;
    }
    return true;
}

//TO DO - calculate if the delay are in the burst window. if not set appropriate delays and return false
//else return true, and the measure will proceed.
bool optimal_path_task::calculate_measurement_delay(const std::set<std::string> &temp_cross_hostaps,
                                                    const std::string &current_hostap,
                                                    const std::string &sta_mac)
{
    calculate_measurement_delay_count++;
    TASK_LOG(DEBUG) << "calculate_measurement_delay_count = "
                    << int(calculate_measurement_delay_count);
    if (calculate_measurement_delay_count == DELAY_COUNT_LIMIT) {
        TASK_LOG(DEBUG) << "calculate_measurement_delay_count == 7 ABORT! delay calculation";
        return true;
    }

    return (ready_to_pick_optimal_path(temp_cross_hostaps, current_hostap, sta_mac));
}

bool optimal_path_task::ready_to_pick_optimal_path(const std::set<std::string> &temp_cross_hostaps,
                                                   const std::string &current_hostap,
                                                   const std::string &sta_mac)
{
    if (!is_measurement_valid(temp_cross_hostaps, current_hostap, sta_mac)) {
        return false;
    } else if (all_measurement_succeed(temp_cross_hostaps, current_hostap, sta_mac)) {
        return true;
    } else if (is_delay_match_window(temp_cross_hostaps, current_hostap)) {
        return true;
    }
    return false;
}

bool optimal_path_task::is_measurement_valid(const std::set<std::string> &temp_cross_hostaps,
                                             const std::string &current_hostap,
                                             const std::string &sta_mac)
{
    int delta_burst = 0;
    //sanity check if delta_burst delay bigger then delta_burst_limit (20 sec)
    delta_burst = (database.get_measurement_recv_delta(current_hostap) / 2);
    if (delta_burst > DELTA_BURST_LIMIT) {
        TASK_LOG(DEBUG) << "delta_burst delay exceed delta_burst_limit = " << int(DELTA_BURST_LIMIT)
                        << " delta_burst_delay = " << int(delta_burst);
        return false;
    }

    auto station = database.get_station(tlvf::mac_from_string(sta_mac));
    if (!station) {
        TASK_LOG(ERROR) << "Station " << sta_mac << " not found";
        return false;
    }

    //iterating on cross hostap to check if all measurement succeed (all IRE captured at list 1)
    int8_t rx_rssi, rx_packets;
    for (auto &hostap : temp_cross_hostaps) {
        auto agent = database.get_agent_by_radio_uid(tlvf::mac_from_string(hostap));
        if (!agent) {
            TASK_LOG(ERROR) << "agent containing radio " << hostap << " not found";
            return false;
        }

        bool is_backhaul_manager =
            (agent->backhaul.wireless_backhaul_radio->radio_uid == tlvf::mac_from_string(hostap));

        std::string hostap_tmp = hostap;
        if (is_backhaul_manager && database.is_node_5ghz(sta_mac)) {
            hostap_tmp = database.get_5ghz_sibling_hostap(hostap);
        }
        if (hostap_tmp.empty() || !station->get_cross_rx_rssi(hostap_tmp, rx_rssi, rx_packets)) {
            TASK_LOG(ERROR) << "can't get cross_rx_rssi for hostap =" << hostap_tmp;
            return false;
        } else if (rx_packets <= -1) {
            change_measurement_window_size(current_hostap, true);
            TASK_LOG(DEBUG) << "rx_packets = " << int(rx_packets) << "increasing window size to: "
                            << int(database.get_measurement_window_size(current_hostap));
            return false;
        }
        TASK_LOG(DEBUG) << "hostap =" << hostap_tmp << " rx_rssi = " << int(rx_rssi)
                        << " rx_packets = " << int(rx_packets);
    }
    return true;
}

bool optimal_path_task::all_measurement_succeed(const std::set<std::string> &temp_cross_hostaps,
                                                const std::string &current_hostap,
                                                const std::string &sta_mac)
{
    auto station = database.get_station(tlvf::mac_from_string(sta_mac));
    if (!station) {
        TASK_LOG(ERROR) << "Station " << sta_mac << " not found";
        return false;
    }

    //iterating on cross hostap to check if all measurement succeed (all IRE captured at list 1)
    int8_t rx_rssi, rx_packets;
    bool all_hostapd_got_packets = false;
    for (auto &hostap : temp_cross_hostaps) {
        auto agent = database.get_agent_by_radio_uid(tlvf::mac_from_string(hostap));
        if (!agent) {
            TASK_LOG(ERROR) << "agent containing radio " << hostap << " not found";
            return false;
        }

        bool is_backhaul_manager =
            (agent->backhaul.wireless_backhaul_radio->radio_uid == tlvf::mac_from_string(hostap));

        std::string hostap_tmp = hostap;
        if (is_backhaul_manager && database.is_node_5ghz(sta_mac)) {
            hostap_tmp = database.get_5ghz_sibling_hostap(hostap);
        }
        if (hostap_tmp.empty() || !station->get_cross_rx_rssi(hostap_tmp, rx_rssi, rx_packets)) {
            TASK_LOG(ERROR) << "can't get cross_rx_rssi for hostap =" << hostap_tmp;
            all_hostapd_got_packets = false;
            break;
        } else if (rx_packets > 4) {
            all_hostapd_got_packets = true;
            TASK_LOG(DEBUG) << "rx_packets > 0 , rx_packets = " << int(rx_packets);
        } else {
            all_hostapd_got_packets = false;
            TASK_LOG(DEBUG) << "rx_packets == 0 , rx_packets = " << int(rx_packets);
            break;
        }

        TASK_LOG(DEBUG) << "hostap =" << hostap_tmp << " rx_rssi = " << int(rx_rssi)
                        << " rx_packets = " << int(rx_packets)
                        << " all_hostapd_got_packets = " << int(all_hostapd_got_packets);
    }
    //if all the hostapd got good result (1 packet and above) from measurement
    if (calculate_measurement_delay_count == 1 && all_hostapd_got_packets) {
        change_measurement_window_size(current_hostap, false);
        TASK_LOG(DEBUG) << "rx_packets = " << int(rx_packets)
                        << "calculate_measurement_delay_count == 1 decreasing window size to: "
                        << int(database.get_measurement_window_size(current_hostap));
    }
    TASK_LOG(DEBUG) << "all_hostapd_got_packets = " << int(all_hostapd_got_packets);
    return all_hostapd_got_packets;
}

bool optimal_path_task::is_delay_match_window(const std::set<std::string> &temp_cross_hostaps,
                                              const std::string &current_hostap)
{
    bool res        = false;
    int delta_burst = 0;
    int delta_max   = 0;
    std::string delta_max_mac;
    auto local_hostaps = temp_cross_hostaps;

    //find the max delay on cross ire
    for (auto &hostap : temp_cross_hostaps) {
        TASK_LOG(DEBUG) << "hostap =" << hostap;
        auto measurement_delay = (database.get_measurement_recv_delta(hostap) / 2);
        if (delta_max <= measurement_delay) {
            delta_max     = measurement_delay;
            delta_max_mac = hostap;
        }
    }

    //the time took burst message arriving to master
    delta_burst = (database.get_measurement_recv_delta(current_hostap) / 2);
    TASK_LOG(DEBUG) << "delta_max_mac =" << delta_max_mac;
    local_hostaps.erase(delta_max_mac);
    int delta_max_sum = delta_max + delta_burst;
    TASK_LOG(DEBUG) << "delta_max_sum =  " << int(delta_max_sum)
                    << " delta_max = " << int(delta_max) << " delta_burst = " << int(delta_burst);

    //max delay:
    //calculated max delay after substracting priv delay
    auto current_hostap_priv_delay = database.get_measurement_delay(current_hostap);
    int actual_max_delay;
    if (delta_max_sum < current_hostap_priv_delay) {
        actual_max_delay = delta_max_sum;
    } else {
        actual_max_delay = (delta_max_sum - current_hostap_priv_delay);
    }

    //checking if max delay match window
    int windows_size = database.get_measurement_window_size(current_hostap);
    TASK_LOG(DEBUG) << "windows_size =" << int(windows_size);

    TASK_LOG(DEBUG) << "actual_max_delay =  " << int(actual_max_delay)
                    << " delta_max_sum = " << int(delta_max_sum)
                    << " current_hostap_priv_delay = " << int(current_hostap_priv_delay);
    float percent1_window_size  = windows_size * ONE_PERCENT;
    float percent80_window_size = windows_size * EIGHTY_PERCENT;
    TASK_LOG(DEBUG) << "actual_max_delay =  " << int(actual_max_delay)
                    << " windows_size = " << int(windows_size)
                    << " percent1_window_size = " << float(percent1_window_size)
                    << " percent80_window_size = " << float(percent80_window_size);
    if ((actual_max_delay > percent1_window_size) && (actual_max_delay < percent80_window_size)) {
        TASK_LOG(DEBUG) << "(actual_max_delay > percent1_window_size) && (actual_max_delay < "
                           "percent80_window_size)";
        res = true;
    } else {
        TASK_LOG(DEBUG) << "actual_max_delay is out of window range!";
        res = false;
    }

    float actual_max_delay_percent = (float(actual_max_delay) / float(windows_size)) * 100;
    TASK_LOG(DEBUG) << "actual_max_delay_percent =" << float(actual_max_delay_percent);
    //calculating the delay for the rest of the ire's
    for (auto &hostap : local_hostaps) {
        int hostap_delta        = (database.get_measurement_recv_delta(hostap) / 2);
        int cross_ap_priv_delay = database.get_measurement_delay(hostap);
        //adding privies delay to meas delay ( beacause do not take in to account in meas)
        int measurement_delay;
        if (delta_max_sum >
            (hostap_delta +
             cross_ap_priv_delay) /*&& (cross_ap_priv_delay < MEAS_MAX_DELAY_ALLOWED)*/) {
            measurement_delay = delta_max_sum - (hostap_delta + cross_ap_priv_delay);
        } else {
            measurement_delay = delta_max_sum - hostap_delta;
        }
        TASK_LOG(DEBUG) << "delta_max_sum  = " << int(delta_max_sum)
                        << " hostap_delta = " << int(hostap_delta)
                        << " cross_ap_priv_delay = " << int(cross_ap_priv_delay)
                        << " measurement_delay = " << int(measurement_delay);
        if (measurement_delay > MEAS_MAX_DELAY_ALLOWED) {
            change_measurement_window_size(current_hostap, true); //true - increasing window
            TASK_LOG(DEBUG) << "change_measurement_window_size - need retry cross - return true!";
            return false;
        }
        //set delay to IRE's:
        //ire with max delay  will set his delay to zero
        database.set_measurement_delay(delta_max_mac, 0);
        TASK_LOG(DEBUG) << "hostap " << delta_max_mac << " max delay ire = 0 __";
        //burst ire will align with with max delay(burst will start with max delay ire meas)
        database.set_measurement_delay(current_hostap, delta_max_sum);
        TASK_LOG(DEBUG) << "current_hostap =" << current_hostap << "  delta_max = " << delta_max
                        << " = delta_max_sum_delay = "
                        << "__ " << delta_max_sum << " __";
        //all other ire's will align with max delay ire.
        database.set_measurement_delay(hostap, measurement_delay);
        TASK_LOG(DEBUG) << "hostap " << hostap << " hostap_measurement_delay = "
                        << "__ " << int(measurement_delay) << " __";
    }

    if ((actual_max_delay_percent < DEC_WINDOW_LIMIT) && (res == false)) {
        change_measurement_window_size(current_hostap, false);
        TASK_LOG(DEBUG) << "change_measurement_window_size - !no need retry cross - return true!";
    }
    return res;
}

void optimal_path_task::change_measurement_window_size(const std::string &current_hostap, bool inc)
{
    auto window_size = database.get_measurement_window_size(current_hostap);
    if (inc) {
        if (window_size < MAX_WINDOW_SIZE) {
            database.set_measurement_window_size(current_hostap,
                                                 (window_size + INC_DEC_WINDOW_STEPS));
            TASK_LOG(DEBUG) << "burst_window_size = "
                            << int(database.get_measurement_window_size(current_hostap));
        } else {
            TASK_LOG(DEBUG) << "burst_window_size = " << int(window_size) << "> 200 ! ending task";
        }
    } else { //dec
        if (window_size > MIN_WINDOW_SIZE) {
            database.set_measurement_window_size(current_hostap,
                                                 (window_size - INC_DEC_WINDOW_STEPS));
            TASK_LOG(DEBUG) << "burst_window_size = "
                            << int(database.get_measurement_window_size(current_hostap));
        }
    }
    return;
}

bool optimal_path_task::get_station_default_capabilities(
    bool is_bandtype_5ghz, beerocks::message::sRadioCapabilities &default_sta_cap)
{
    if (is_bandtype_5ghz) {
        //default values are set so that the decision is more towards 5GHZ....
        default_sta_cap.ht_mcs               = 7;
        default_sta_cap.vht_mcs              = 9;
        default_sta_cap.ht_ss                = 2;
        default_sta_cap.vht_ss               = 2;
        default_sta_cap.ht_bw                = 1;
        default_sta_cap.vht_bw               = 2;
        default_sta_cap.ht_low_bw_short_gi   = 1;
        default_sta_cap.ht_high_bw_short_gi  = 1;
        default_sta_cap.vht_low_bw_short_gi  = 1;
        default_sta_cap.vht_high_bw_short_gi = 0;
        default_sta_cap.ant_num              = 2;
        default_sta_cap.wifi_standard        = beerocks::STANDARD_AC;
        return true;
    } else {
        //return default values....
        default_sta_cap.ht_mcs               = 7;
        default_sta_cap.vht_mcs              = 0;
        default_sta_cap.ht_ss                = 1;
        default_sta_cap.vht_ss               = 0;
        default_sta_cap.ht_bw                = 0;
        default_sta_cap.vht_bw               = 0;
        default_sta_cap.ht_low_bw_short_gi   = 1;
        default_sta_cap.ht_high_bw_short_gi  = 0;
        default_sta_cap.vht_low_bw_short_gi  = 0;
        default_sta_cap.vht_high_bw_short_gi = 0;
        default_sta_cap.ant_num              = 1;
        default_sta_cap.wifi_standard        = beerocks::STANDARD_N;
        return true;
    }
}

double optimal_path_task::calculate_weighted_phy_rate(const Station &client)
{
    auto if_type = database.get_node_backhaul_iface_type(tlvf::mac_to_string(client.mac));

    if (if_type == beerocks::IFACE_TYPE_ETHERNET) {
        //TODO FIXME --> get ethernet speed
        return (1e+5 * double(beerocks::BRIDGE_RATE_100KB));
    } else {
        return client.cross_estimated_tx_phy_rate;
    }
}

bool optimal_path_task::is_hostap_on_cs_process(const std::string &hostap_mac)
{
    if (database.get_hostap_on_dfs_reentry(tlvf::mac_from_string(hostap_mac)) ||
        (database.is_node_5ghz(hostap_mac) &&
         database.get_hostap_is_dfs(tlvf::mac_from_string(hostap_mac)) &&
         !database.get_hostap_cac_completed(tlvf::mac_from_string(hostap_mac)))) {
        TASK_LOG(DEBUG) << "is_hostap_on_cs_process return true";
        return true;
    }
    return false;
}

template <typename C>
void optimal_path_task::remove_all_client_non_selected_band_radios(C &radios,
                                                                   const sMacAddr &client_mac)
{
    if (radios.empty()) {
        TASK_LOG(ERROR) << "Candidate list is empty, nothing to remove";
        return;
    }

    auto client = database.get_station(client_mac);
    if (!client) {
        TASK_LOG(ERROR) << "Client " << client_mac << " not found";
        return;
    }

    // Remove all non selected bands from potential steering target list and continue
    // with optimal path task
    auto it = radios.begin();
    while (it != radios.end()) {
        if (!database.is_hostap_on_client_selected_bands(client_mac,
                                                         tlvf::mac_from_string(it->first))) {
            TASK_LOG(INFO) << "Remove candidate " << it->first
                           << " since its not on one of client's selected bands "
                           << int(client->selected_bands);
            it = radios.erase(it);
        } else {
            ++it;
        }
    }
}

bool optimal_path_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{
    return false;
}
