//
// Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//

#include "vbss_manager.h"
#include "../../../vbss/vbss_actions.h"

namespace vbss {

VbssManager::VbssManager(son::db &db, std::shared_ptr<beerocks::TimerManager> timer_manager)
    : m_database(db), m_timer_manager(timer_manager)
{
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
    bool ret_val = true;
    auto agent   = m_database.m_agents.get(agent_mac);
    if (!agent) {
        LOG(ERROR) << "Agent mac address does not exist in database: " << agent_mac;
        return false;
    }
    // Iterate over the map, making the list of available vbss id's then store in db
    for (auto const &it : ruid_cap_map) {
        auto radio_id       = it.first;
        auto radio_caps     = it.second.get();
        auto radio_instance = agent->radios.get(radio_id);
        //Get a bssid in use so we can make the different iterations
        auto base_bssid = radio_instance->bsses.begin()->first;

        if (radio_caps->apply_vbssid_restrict) {
            if (radio_caps->apply_vbssid_match_mask_restrict ||
                radio_caps->apply_fixed_bits_restrict) {
                std::vector<vbss_id> vbss_id_list;

                if (create_set_of_vbss_ids(base_bssid.oct, radio_caps->fixed_bits_mask.oct,
                                           radio_caps->fixed_bits_value.oct, radio_caps->max_vbss,
                                           vbss_id_list)) {
                    // Clear out old list of used vbss ids treating this as new
                    agent->radios[radio_id]->vbss_ids_used.clear();
                    for (auto const &id_it : vbss_id_list) {
                        // Copy list of available vbss ids to the agent db object
                        sMacAddr avail_id;
                        std::copy_n(id_it.data(), ETH_ALEN, avail_id.oct);
                        agent->radios[radio_id]->vbss_ids_used[avail_id] = false;
                    }
                    agent->radios[radio_id]->has_vbss_restrictions = true;
                } else {
                    LOG(ERROR) << "Failed to create vbss id list for radio " << radio_id;
                    ret_val = false;
                    continue;
                }
            }
        }
        // Set agent to vbss capable along with other information
        agent->does_support_vbss = true;
        agent->radios[radio_id]->vbss_radio    = true;
        agent->radios[radio_id]->max_vbss      = radio_caps->max_vbss;
        agent->radios[radio_id]->vbss_subtract = radio_caps->vbsses_subtract;
        LOG(DEBUG) << "Added vbss capable radio: " << radio_id << std::endl
                   << "On agent with mac: " << agent_mac << std::endl
                   << "Max number of vbss supported is: " << agent->radios[radio_id]->max_vbss
                   << std::endl;
    }
    return ret_val;
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
    if (!radio->vbss_radio) {
        LOG(ERROR) << "Radio: " << radio->radio_uid
                   << " is not capable of supporting vbss functionality" << std::endl;
        return false;
    }

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
    vbss::sClientVBSS tmp_vbss{.vbssid = vbssId, .client_mac = c_mac, .client_is_associated = false};
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
        if (it.second == false) {
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
    for (auto const &it : m_database.m_stations) {
        // We only care about the vstations
        auto client = it.second.get();
        if (!client->get_vsta_status()) {
            continue;
        }
        // Determine which Agent has reported the best RSSI

        //
    }
}

} // namespace vbss
