//
// Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//

#include "vbss_manager.h"
#include "../../../vbss/vbss_actions.h"

namespace vbss {

VbssManager::VbssManager(son::db &db, std::shared_ptr<beerocks::TimerManager> timer_manager,
                         bool nbapiControl, bool legacyMode)
    : m_database(db), m_timer_manager(timer_manager), m_controlled_by_nbapi(nbapiControl),
      m_use_legacy_steering(legacyMode)
{
    m_current_num_vbss         = 0;
    m_max_num_vbss_system      = 0;
    last_sent_unassociated_mid = 0;
    LOG_IF(!m_timer_manager, FATAL) << "Timer manager is a null pointer!";
}

VbssManager::~VbssManager(){};

bool VbssManager::initialize()
{
    // Do initialization tasks
    // Place holder for future placements

    // Set up timer
    m_client_analysis_timer =
        m_timer_manager->add_timer("VBSS Client analyze", ANALYZE_VSTA_VBSS, ANALYZE_VSTA_VBSS,
                                   [&](int fd, beerocks::EventLoop &loop) {
                                       analyze_clients();
                                       return true;
                                   });
    return true;
}

bool VbssManager::analyze_radio_restriction(
    const sMacAddr &agent_mac,
    const beerocks::mac_map<vbss::sAPRadioVBSSCapabilities> &ruid_cap_map)
{
    LOG(DEBUG) << "Analyzing radio VBSS capabilities for agent " << agent_mac;

    bool ret_val = true;
    auto agent   = m_database.m_agents.get(agent_mac);
    if (agent == nullptr) {
        LOG(ERROR) << "Agent mac address does not exist in database: " << agent_mac;
        return false;
    }

    // Iterate over the map, making the list of available vbss id's then store in db
    for (auto const &it : ruid_cap_map) {
        auto radio_id = it.first;
        // These values should remain static during the life of a radio therefor if we get another request
        // For now will ignore
        if (m_radio_vbss_capable_received.find(radio_id) != m_radio_vbss_capable_received.end()) {
            // TODO: add comparison funciton to verify nothing had changed
            continue;
        }
        auto radio_caps     = it.second.get();
        auto radio_instance = agent->radios.get(radio_id);
        if (radio_instance == nullptr) {
            LOG(ERROR) << "Can't find radio with ID: " << radio_id
                       << " associated with agent: " << agent_mac;
            continue;
        }

        if (radio_instance->bsses.size() == 0) {
            LOG(INFO) << "No known BSSes yet for radio with UID " << radio_id;
            continue;
        }

        //Get a bssid in use so we can make the different iterations
        auto base_bssid = radio_instance->bsses.begin()->first;
        LOG(DEBUG) << "Creating bss map for radio: " << radio_id;
        if (radio_caps->apply_vbssid_restrict) {
            if (radio_caps->apply_vbssid_match_mask_restrict ||
                radio_caps->apply_fixed_bits_restrict) {
                std::vector<vbss_id> vbss_id_list;

                if (create_set_of_vbss_ids(base_bssid.oct, radio_caps->fixed_bits_mask.oct,
                                           radio_caps->fixed_bits_value.oct, radio_caps->max_vbss,
                                           vbss_id_list)) {
                    // Clear out old list of used vbss ids treating this as new
                    radio_instance->vbss_ids_used.clear();
                    for (auto const &id_it : vbss_id_list) {
                        // Copy list of available vbss ids to the agent db object
                        sMacAddr avail_id;
                        std::copy_n(id_it.data(), ETH_ALEN, avail_id.oct);
                        radio_instance->vbss_ids_used[avail_id] = false;
                        m_global_vbssid_map[avail_id]           = false;
                    }
                    //agent->radios[radio_id]->has_vbss_restrictions = true;
                    radio_instance->has_vbss_restrictions = true;
                } else {
                    LOG(ERROR) << "Failed to create vbss id list for radio " << radio_id;
                    ret_val = false;
                    continue;
                }
            }
        }
        //Set agent to vbss capable along with other information
        agent->does_support_vbss           = true;
        radio_instance->vbss_capable_radio = true;
        radio_instance->current_vbss_used  = 0;
        radio_instance->max_vbss           = radio_caps->max_vbss;
        radio_instance->vbss_subtract      = radio_caps->vbsses_subtract;
        LOG(DEBUG) << "Added vbss capable radio: " << radio_id << std::endl
                   << "On agent with mac: " << agent_mac << std::endl
                   << "Max number of vbss supported is: " << radio_instance->max_vbss << std::endl;
        if (m_max_num_vbss_system == 0 || radio_instance->max_vbss < m_max_num_vbss_system) {
            // Currently the rudementary idea would be to handle the worst case scenario that
            // every client could make it to the radio with the least amount of vbss
            // In this instance we would want to verify that we could support everyone equally
            m_max_num_vbss_system = radio_instance->max_vbss;
        }
        m_radio_vbss_capable_received[radio_id] = true;
    }
    // This only matters if using legacy steering
    if (!m_use_legacy_steering && (m_max_num_vbss_system != m_unused_ssid_extensions.size() +
                                                                m_used_ssid_extensions.size())) {
        // This is brute force and ugly, but it'll work
        if (m_max_num_vbss_system >
            m_unused_ssid_extensions.size() + m_used_ssid_extensions.size()) {
            auto num_to_make = (m_max_num_vbss_system - m_used_ssid_extensions.size()) -
                               m_unused_ssid_extensions.size();
            for (uint i = 0; i < num_to_make; ++i) {
                std::string ssid_extention = "_vbss_" + std::to_string(i);
                const auto &used_it        = std::find(m_used_ssid_extensions.begin(),
                                                       m_used_ssid_extensions.end(), ssid_extention);
                if (used_it != m_used_ssid_extensions.end())
                    continue;
                const auto &unused_it = std::find(m_unused_ssid_extensions.begin(),
                                                  m_unused_ssid_extensions.end(), ssid_extention);
                if (unused_it != m_unused_ssid_extensions.end())
                    continue;
                m_unused_ssid_extensions.push_back(ssid_extention);
            }
        } else if (m_max_num_vbss_system > m_used_ssid_extensions.size()) {
            m_unused_ssid_extensions.resize(
                (m_max_num_vbss_system - m_used_ssid_extensions.size()));
        } else {
            m_unused_ssid_extensions.clear();
        }
    }
    return ret_val;
}

bool VbssManager::find_and_create_vbss(const sMacAddr &agent_mac, vbss::sCreationEvent &crtn_Struct)
{
    auto agent = m_database.m_agents.get(agent_mac);
    if (!agent) {
        LOG(ERROR) << "Agent with address " << agent_mac << " not found";
        return false;
    }
    if (!agent->does_support_vbss) {
        LOG(ERROR) << "Agent " << agent_mac << " does not support vbss";
        return false;
    }
    if (!can_system_have_another_vbss()) {
        LOG(ERROR) << "The overall network can not support another VBSS we are at capacity";
        return false;
    }
    // If we are here, we can safely assume this agent has a radio which supports vbss
    // as well as has space for a vbss to be instantiated
    // So lets find a radio and get the process started
    // Just going to brute force this
    for (auto &radio_it : agent->radios) {
        auto radio = radio_it.second;
        if (!radio->vbss_capable_radio)
            continue;
        // Verify this won't put us over the radio limit
        if ((radio->num_legacy_bss + radio->current_vbss_used + 1) > radio->max_vbss)
            continue;
        // lets bruteforce our way to an open vbss
        for (const auto &bss : radio->bsses) {
            // get the ssid of an already operating bss, now find the configuration info to match it
            // if we are enabled; go forth and copy
            if (bss.second->enabled) {
                auto wifi_channel =
                    m_database.get_node_wifi_channel(tlvf::mac_to_string(bss.second->bssid));
                // Currently only push for this on 5G radios
                if (!wifi_channel.is_empty()) {
                    if (wifi_channel.get_freq_type() != beerocks::eFreqType::FREQ_5G)
                        continue;
                }
                auto bss_info_list = m_database.get_bss_info_configuration(agent_mac);
                for (const auto &bss_info : bss_info_list) {
                    if (bss_info.ssid == bss.second->ssid) {
                        sMacAddr vbssId;
                        if (!find_available_vbssid(radio->radio_uid, vbssId)) {
                            LOG(ERROR) << "Unable to find a VBSS ID on radio " << radio->radio_uid;
                            return false;
                        }
                        std::string ssid_extension         = m_unused_ssid_extensions.back();
                        crtn_Struct.client_vbss.vbssid     = vbssId;
                        crtn_Struct.client_vbss.client_mac = {};
                        crtn_Struct.client_vbss.client_is_associated = false;
                        crtn_Struct.dest_ruid                        = radio->radio_uid;
                        crtn_Struct.ssid         = bss_info.ssid + ssid_extension;
                        crtn_Struct.password     = bss_info.network_key;
                        crtn_Struct.sec_ctx_info = nullptr;
                        LOG(DEBUG) << "Creation info successfully found for VBSS ID: " << vbssId
                                   << "\n On radio: " << radio->radio_uid
                                   << "\nWith SSID: " << crtn_Struct.ssid;
                        // Store for fast look up later
                        vbss::VbssManager::sOpenVbssStatus vbssStatus;
                        vbssStatus.vbss_id        = vbssId;
                        vbssStatus.create_sent    = true;
                        vbssStatus.create_success = false;
                        m_open_vbsses[agent_mac]  = vbssStatus;
                        // book keeping
                        m_used_ssid_extensions.push_back(ssid_extension);
                        m_unused_ssid_extensions.pop_back();
                        return true;
                    }
                }
            }
        }
    }
    // If we get here then no radio was capable of running vbss (-_-)
    // Something is wrong with our logic
    LOG(DEBUG) << "We did not find a available radio to run a vbss on agent " << agent_mac;
    return false;
}

bool VbssManager::handle_vbss_creation(const sMacAddr &radio_mac, const sMacAddr &vbss_id)
{
    auto radio = m_database.get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with radio mac: " << radio_mac;
        return false;
    }
    auto agent = m_database.get_agent_by_radio_uid(radio_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to get agent hosting radio uid: " << radio_mac;
        return false;
    }
    // Perhaps move this to when we try to create
    // May or may not create race condition
    radio->vbss_ids_used[vbss_id]               = true;
    m_global_vbssid_map[vbss_id]                = true;
    m_open_vbsses[agent->al_mac].create_success = true;
    ++m_current_num_vbss;
    LOG(DEBUG) << "We now have " << m_current_num_vbss << " vbss running";
    return true;
}

bool VbssManager::handle_station_connect(const vbss::sStationConnectedEvent &stationConnect)
{
    // Do some book keeping
    auto client = m_database.get_station(stationConnect.client_mac);
    if (!client) {
        // This shouldn't happen
        LOG(ERROR) << "Failed to find station with mac: " << stationConnect.client_mac;
        return false;
    }
    client->set_vsta_status(true);
    auto agent = m_database.get_agent_by_bssid(stationConnect.bss_id);
    if (!agent) {
        LOG(ERROR) << "Failed to find agent hosting bssid: " << stationConnect.bss_id;
        return false;
    }
    auto radio = m_database.get_radio_by_bssid(stationConnect.bss_id);
    if (!radio) {
        LOG(ERROR) << "Failed to find radio by bssid: " << stationConnect.bss_id;
    }
    m_client_agent[stationConnect.client_mac] = agent->al_mac;
    if (m_open_vbsses.find(agent->al_mac) != m_open_vbsses.end()) {
        if (m_open_vbsses[agent->al_mac].vbss_id == stationConnect.bss_id) {
            //Erase the open vbss list
            m_open_vbsses.erase(agent->al_mac);
        }
    }
    sVStaStats clientStats;
    clientStats.vbss_id                     = stationConnect.bss_id;
    clientStats.cur_ruid                    = radio->radio_uid;
    m_vsta_stats[stationConnect.client_mac] = clientStats;

    return register_client_for_rssi(stationConnect);
}

bool VbssManager::handle_success_move(const sMacAddr &sta_mac, const sMacAddr &cur_ruid,
                                      const sMacAddr &old_ruid)
{
    // First need to update unassociated station model
    bool ret_val = true;
    LOG(DEBUG) << "handling success move";
    std::vector<sMacAddr> not_connected_agents;
    auto n_agent = m_database.get_agent_by_radio_uid(cur_ruid);
    if (!n_agent) {
        LOG(ERROR) << "Failed to find the agent for the new connected radio" << cur_ruid;
        return false;
    }
    for (auto &agent : m_database.get_all_connected_agents()) {
        LOG(DEBUG) << "Comparing " << agent->al_mac << " to " << n_agent->al_mac;
        if (agent->al_mac != n_agent->al_mac) {
            not_connected_agents.push_back(agent->al_mac);
            LOG(DEBUG) << "Added " << agent->al_mac;
        }
    }
    if (!m_database.update_unassociated_station_agents(sta_mac, not_connected_agents)) {
        LOG(ERROR) << "Failed to update the unassociated station agents list";
        ret_val = false;
    }
    const auto &iter = std::find(m_cur_move_vbssid.begin(), m_cur_move_vbssid.end(),
                                 m_vsta_stats[sta_mac].vbss_id);
    m_cur_move_vbssid.erase(iter);
    m_vsta_stats[sta_mac].next_best_agent  = {};
    m_vsta_stats[sta_mac].next_best_count  = 0;
    m_vsta_stats[sta_mac].next_best_rssi   = -120;
    m_vsta_stats[sta_mac].move_in_progress = false;
    m_vsta_stats[sta_mac].cur_ruid         = cur_ruid;
    m_client_agent[sta_mac]                = n_agent->al_mac;
    return ret_val;
}

bool VbssManager::handle_station_disconnect(const vbss::sStationDisconEvent &stationDisconn,
                                            vbss::sDestructionEvent &destroyEvent)
{
    auto radio = m_database.get_radio_by_bssid(stationDisconn.client_vbss.vbssid);
    if (!radio) {
        LOG(ERROR) << "Failed to find radio with bss id: " << stationDisconn.client_vbss.vbssid;
        return false;
    }
    // update that vbss id is no longer being used
    //radio->vbss_ids_used[stationDisconn.client_vbss.vbssid] = false;
    m_client_agent.erase(stationDisconn.client_vbss.client_mac);

    m_vsta_stats.erase(stationDisconn.client_vbss.client_mac);

    destroyEvent.client_vbss         = stationDisconn.client_vbss;
    destroyEvent.should_disassociate = false;
    LOG(DEBUG) << "Station: " << stationDisconn.client_vbss.client_mac << " has disconnected\n"
               << "From VBSS ID: " << stationDisconn.client_vbss.vbssid
               << "\nReported by Topology: " << stationDisconn.from_topology_notification;
    return true;
}

bool VbssManager::process_vsta_stats_event(const vbss::sUnassociatedStatsEvent &unassociated_stats,
                                           bool &shouldMove,
                                           std::vector<vbss::sMoveEvent> &moveVals)
{
    bool ret_val = false;
    // First thing first compare MID
    //std::chrono::time_point<std::chrono::steady_clock> start_time =
    //   std::chrono::steady_clock::now();
    if (last_sent_unassociated_mid > unassociated_stats.mmid) {
        LOG(ERROR) << "Recieved stale data, expected MID = or great: " << last_sent_unassociated_mid
                   << "Got " << unassociated_stats.mmid << " instead";
        return false;
    }
    for (auto &sta_stat : unassociated_stats.station_stats) {
        sMacAddr sta_mac    = std::get<0>(sta_stat);
        int8_t incomingStat = son::wireless_utils::convert_rssi_from_rcpi(std::get<1>(sta_stat));
        if (m_vsta_stats.find(sta_mac) == m_vsta_stats.end()) {
            // TODO: Think about how to handle this, should not happen
            continue;
        }
        // Get the current value from database
        auto station = m_database.get_station(sta_mac);
        if (!station) {
            LOG(ERROR) << "Failed to find station in database with mac: " << sta_mac;
            continue;
        }
        int8_t curRssi;
        int8_t throwAwayPackets;
        std::chrono::duration<double> ts;
        if (!station->get_cross_rx_rssi(tlvf::mac_to_string(m_vsta_stats[sta_mac].cur_ruid),
                                        curRssi, throwAwayPackets, ts)) {
            LOG(ERROR) << "Failed to recieve current RSSI from current agent for station: "
                       << sta_mac;
            continue;
        }
        //auto duration = std::chrono::duration<std::chrono::seconds>(start_time - ts).count();
        if (ts.count() > 2) {
            LOG(INFO) << "We are comparing against old rssi data, it's been " << ts.count()
                      << "s since last associated rssi came in for station=" << sta_mac
                      << " relative to radio " << m_vsta_stats[sta_mac].cur_ruid;
            continue;
        }
        if (compare_incoming_to_curr(curRssi, incomingStat)) {
            // This means the incoming is better
            if (m_vsta_stats[sta_mac].next_best_agent == unassociated_stats.agent_mac) {
                // We got a repeater
                if (m_vsta_stats[sta_mac].move_in_progress) {
                    continue;
                }
                m_vsta_stats[sta_mac].next_best_count++;
                m_vsta_stats[sta_mac].next_best_rssi = incomingStat;
                if (m_vsta_stats[sta_mac].next_best_count > BEST_MOVE_COUNT) {
                    LOG(DEBUG) << "We found a radio that's better to move to";
                    auto radio = m_database.get_radio_by_bssid(m_vsta_stats[sta_mac].vbss_id);
                    if (!radio) {
                        LOG(ERROR) << "Failed to get radio associated with VBSS: "
                                   << m_vsta_stats[sta_mac].vbss_id;
                        ret_val = false;
                        continue;
                    }
                    auto bss = m_database.get_bss(m_vsta_stats[sta_mac].vbss_id);
                    if (!bss) {
                        LOG(ERROR) << "Failed to get BSS object with vbssid: "
                                   << m_vsta_stats[sta_mac].vbss_id;
                        continue;
                    }
                    shouldMove = true;
                    vbss::sMoveEvent moveEventVals;
                    moveEventVals.client_vbss.vbssid               = m_vsta_stats[sta_mac].vbss_id;
                    moveEventVals.client_vbss.client_is_associated = true;
                    moveEventVals.client_vbss.client_mac           = sta_mac;
                    moveEventVals.dest_ruid                        = std::get<2>(sta_stat);
                    moveEventVals.ssid                             = bss->ssid;
                    moveEventVals.client_vbss.current_connected_ruid = radio->radio_uid;
                    moveVals.push_back(moveEventVals);
                    m_cur_move_vbssid.push_back(m_vsta_stats[sta_mac].vbss_id);
                    m_vsta_stats[sta_mac].move_in_progress = true;
                }
            } else {
                // New best
                m_vsta_stats[sta_mac].next_best_agent  = unassociated_stats.agent_mac;
                m_vsta_stats[sta_mac].next_best_count  = 1;
                m_vsta_stats[sta_mac].next_best_rssi   = incomingStat;
                m_vsta_stats[sta_mac].move_in_progress = false;
            }
        }
    }

    return ret_val;
}

bool VbssManager::handle_vbss_destruction(const sMacAddr &vbssid)
{
    auto radio = m_database.get_radio_by_bssid(vbssid);
    if (!radio) {
        LOG(ERROR) << "Failed to find radio associated with vbssid: " << vbssid;
        return false;
    }
    radio->vbss_ids_used[vbssid] = false;
    const auto &iter = std::find(m_cur_move_vbssid.begin(), m_cur_move_vbssid.end(), vbssid);
    if (iter == m_cur_move_vbssid.end()) {
        // This is not a move update global map
        m_global_vbssid_map[vbssid] = false;
    }
    auto vbss = m_database.get_bss(vbssid);
    if (!vbss) {
        LOG(ERROR) << "Failed to find instance of vbss object in database";
        return false;
    }
    // Get the vbss substring to place back in unused vbss options
    std::size_t pos           = vbss->ssid.find("_vbss_");
    std::string ssid_addition = vbss->ssid.substr(pos);
    m_unused_ssid_extensions.push_back(ssid_addition);
    --m_current_num_vbss;
    return true;
}

// Assumption is that there is at least >1 agent in network
bool VbssManager::register_client_for_rssi(const vbss::sStationConnectedEvent &stationConnect)
{
    //First find all agents that client is connected to
    //Create list, then pass this information into db
    auto conn_agent = m_database.get_agent_by_bssid(stationConnect.bss_id);
    if (!conn_agent) {
        LOG(ERROR) << "Failed to find agent connected to vbss " << stationConnect.bss_id;
        return false;
    }
    std::vector<sMacAddr> not_connected_agents;
    for (auto &agent : m_database.get_all_connected_agents()) {
        LOG(DEBUG) << "Connected to agent: " << conn_agent->al_mac << "\n Looking at Agent "
                   << agent->al_mac;
        if (agent->al_mac != conn_agent->al_mac)
            not_connected_agents.push_back(agent->al_mac);
    }
    LOG(DEBUG) << "Agent list is " << not_connected_agents.size();
    if (not_connected_agents.size()) {
        if (!m_database.add_unassociated_station(stationConnect.client_mac, stationConnect.channel,
                                                 stationConnect.op_class, not_connected_agents)) {
            LOG(ERROR) << "Failed to add " << stationConnect.client_mac
                       << " to the unassociated station database";
            return false;
        }
    }
    return true;
}

bool VbssManager::can_radio_support_another_vbss(const sMacAddr &agent_mac, const sMacAddr &bssid)
{
    // First get radio that the BSS is currently associated on
    auto radio = m_database.get_radio_by_bssid(bssid);
    if (!radio) {
        LOG(ERROR) << "Radio hosting bss id: " << bssid
                   << " not found, vbss analysis failed new client" << std::endl;
        return false;
    }
    // if (!radio->vbss_radio) {
    //     LOG(ERROR) << "Radio: " << radio->radio_uid
    //                << " is not capable of supporting vbss functionality" << std::endl;
    //     return false;
    // }

    if (radio->current_vbss_used >= radio->max_vbss) {
        LOG(ERROR) << "Radio with id: " << radio->radio_uid << " has no space for a vbss!"
                   << std::endl;
        return false;
    }

    LOG(DEBUG) << "Radio with id: " << radio->radio_uid << " has space for a vbss!" << std::endl;
    return false;
}

// This method should only be used in the event that a client has connected to an old none virtual bss
bool VbssManager::attempt_move_associated_client(const sMacAddr &agent_mac,
                                                 const sMacAddr &cur_bssid, const sMacAddr &c_mac)
{
    auto radio = m_database.get_radio_by_bssid(cur_bssid);
    if (!radio) {
        LOG(ERROR) << "Radio hosting bssid: " << cur_bssid << " Not found" << std::endl;
        return false;
    }
    auto c_bss = m_database.get_bss(cur_bssid);
    if (!c_bss) {
        LOG(ERROR) << "Cannot find bss: " << cur_bssid;
        return false;
    }

    // Find an available vbss id
    sMacAddr vbssId;
    if (!find_available_vbssid(radio->radio_uid, vbssId)) {
        LOG(ERROR) << "Unable to find new VBSS ID on radio " << radio->radio_uid << std::endl
                   << " On agent: " << agent_mac;
        return false;
    }

    // We need to send down the create vbss functionality
    vbss::sClientVBSS tmp_vbss{
        .vbssid = vbssId, .client_mac = c_mac, .client_is_associated = false};
    auto bss_info_list = m_database.get_bss_info_configuration(agent_mac);
    //There should be a better way to get this. For now going to brute force...
    for (const auto &bss_info : bss_info_list) {
        // This is currently the only information I have to attempt to find the right network encryption info
        // Need to make PM to make this better/easier to search for
        if (bss_info.ssid == c_bss->ssid) {
            // send the create vbss
            if (!vbss_actions::create_vbss(tmp_vbss, radio->radio_uid, bss_info.ssid,
                                           bss_info.network_key, nullptr, m_database)) {
                LOG(ERROR) << "Failed to perform create vbss on agent " << agent_mac << std::endl
                           << "With radio id " << radio->radio_uid;
            }
            LOG(DEBUG)
                << "Sending down create vbss to initiate client steering from regular bss to vbss";
            // we were successful so store vbss, client relationship for a temp time until we know it was succesful or not.
            auto ret_val = m_pre_associated_clients.emplace(vbssId, c_mac);
            if (ret_val.second == false) {
                //That vbss id already existed, update to be with new client
                m_pre_associated_clients[vbssId] = c_mac;
            }
            return true;
        }
    }
    LOG(ERROR) << "Could not find the appropriate bss info for: " << c_bss->bssid;
    return false;
}

bool VbssManager::handle_vbss_for_associated_client(const sMacAddr &agent_mac,
                                                    const sMacAddr &bssid)
{
    auto client_it = m_pre_associated_clients.find(bssid);
    if (client_it == m_pre_associated_clients.end()) {
        LOG(ERROR) << "Could not find client associated with vbss: " << bssid;
        return false;
    }
    auto client = client_it->second;

    // Now we need to kick off the client steering task
    auto controller = m_database.get_controller_ctx();
    if (!controller) {
        LOG(ERROR) << "Failed to get controller context";
        return false;
    }

    if (!controller->start_client_steering(tlvf::mac_to_string(client.oct),
                                           tlvf::mac_to_string(bssid.oct))) {
        LOG(ERROR) << "Failed to launch client steering task for associated sta " << client
                   << " onto vbssid: " << bssid;
        return false;
    }
    // Possibly remove
    return true;
}

bool VbssManager::find_available_vbssid(const sMacAddr &radio_mac, sMacAddr &nVbss_id)
{
    auto radio = m_database.get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Radio can not be found";
        return false;
    }
    for (const auto &it : radio->vbss_ids_used) {
        if (it.second == false && m_global_vbssid_map[it.first] == false) {
            std::copy_n(it.first.oct, ETH_ALEN, nVbss_id.oct);
            return true;
        }
    }
    return false;
}

void VbssManager::analyze_clients()
{
    // Get list of all Clients
    // Iterate over the clients to verify in the best connection
    /*
    for (auto const &it : m_database.m_stations) {
        // We only care about the vstations
        auto client = it.second.get();
        if (!client->get_vsta_status()) {
            continue;
        }
        // Determine which Agent has reported the best RSSI

        //
    }
    */
    // Since this is structured differently, we will once a second just send out request
    if (m_database.get_unassociated_stations().size()) {
        auto cntrlCntx = m_database.get_controller_ctx();
        if (!cntrlCntx) {
            LOG(ERROR) << "Failed to get the controller context for VBSS Manager";
        }
        cntrlCntx->get_unassociated_stations_stats();
    }
}

bool VbssManager::can_system_have_another_vbss()
{
    return ((m_current_num_vbss + 1) <= m_max_num_vbss_system);
}

bool VbssManager::currently_have_vbss_free(const sMacAddr &agent_mac)
{
    const auto ret_val = m_open_vbsses.find(agent_mac);
    return (ret_val != m_open_vbsses.end()) ? true : false;
}

} // namespace vbss
