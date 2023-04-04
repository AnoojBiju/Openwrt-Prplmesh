//
// Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//
#include "../../../vbss/vbss_actions.h"
#include "../../../vbss/vbss_core.h"
#include "./db/db.h"

#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_timer_manager.h>
#include <bcl/network/file_descriptor.h>

#ifndef VBSS_MANAGER_H
#define VBSS_MANAGER_H

namespace vbss {

struct sAPRadioVBSSCapabilities {
    uint8_t max_vbss;
    bool vbsses_subtract;
    bool apply_vbssid_restrict;
    bool apply_vbssid_match_mask_restrict;
    bool apply_fixed_bits_restrict;
    sMacAddr fixed_bits_mask;
    sMacAddr fixed_bits_value;

    sAPRadioVBSSCapabilities(sMacAddr ruid, sAPRadioVBSSCapabilities &caps)
        : sAPRadioVBSSCapabilities(caps)
    {
    }
    sAPRadioVBSSCapabilities() {}
};

class VbssManager : public VbssCore {

public:
    VbssManager(son::db &db, std::shared_ptr<beerocks::TimerManager> timer_manager,
                bool nbapiControl = false, bool legacyMode = false);

    ~VbssManager();

    /*
    * @brief Initailizes the VbssManager and sets up the Timer Manager
    *
    * @return true on success and false otherwise
    */
    bool initialize();

    bool analyze_radio_restriction(
        const sMacAddr &agent_mac,
        const beerocks::mac_map<vbss::sAPRadioVBSSCapabilities> &ruid_cap_map);

    /**
     * @brief Does this radio currently have a open vbss
     * 
     * @param agent_mac Mac Address of agent to see
     * @return true if there is a free vbss open
     * @return false if no open vbss exists on this agent
     */
    bool currently_have_vbss_free(const sMacAddr &agent_mac);

    /**
     * @brief Find what open Vbss will exist on this agent
     * 
     * @param agent_mac Mac address of agent to create vbss
     * @param crtn_Struct Struct to pass back to caller full on information to be passed to vbss task
     * @return true If a vbss was 
     * @return false 
     */
    bool find_and_create_vbss(const sMacAddr &agent_mac, vbss::sCreationEvent &crtn_Struct);

    /// @brief Analyze if radio can support vbss along with another client; to see if moving to vbss is possible
    /// @param agent_mac
    /// @param bssid
    /// @return true if possible to move; false if radio agent couldn't support the vbss operation
    bool can_radio_support_another_vbss(const sMacAddr &agent_mac, const sMacAddr &bssid);

    /**
     * @brief Handle the response from radio when successful Vbss Creation
     * 
     * @param radio_mac Radio that created vbss
     * @param vbssid Id of vbss
     * @return true if no errors
     * @return false if errors
     */
    bool handle_vbss_creation(const sMacAddr &radio_mac, const sMacAddr &vbss_id);

    /**
     * @brief Book keeping for when a station successfully connects to a vbss
     * 
     * @param stationConnect 
     * @return true 
     * @return false 
     */
    bool handle_station_connect(const vbss::sStationConnectedEvent &stationConnect);

    /**
     * @brief Book keeping of when station disconnects along with making a destroy
     *          vbss event message
     * 
     * @param stationDisconn information about disconnected station
     * @param destroyEvent Event to be passed back to caller to send to vbss task
     * @return true 
     * @return false 
     */
    bool handle_station_disconnect(const vbss::sStationDisconEvent &stationDisconn,
                                   vbss::sDestructionEvent &destroyEvent);

    /// @brief Book keeping for when a vbss is destroyed
    /// @param vbssid
    /// @return
    bool handle_vbss_destruction(const sMacAddr &vbssid);

    bool process_vsta_stats_event(const vbss::sUnassociatedStatsEvent &unassociated_stats,
                                  bool &shouldMove, std::vector<vbss::sMoveEvent> &moveVals);

    bool handle_success_move(const sMacAddr &sta_mac, const sMacAddr &cur_ruid,
                             const sMacAddr &old_ruid);

    struct sVStaStats {
        // In the future this should be a list, by rssi values
        // TODO: MAKE THIS DYNAMIC, RSSI VALUE, BEST COUNTS, ETC.
        sMacAddr vbss_id;
        sMacAddr cur_ruid;
        sMacAddr next_best_agent;
        sMacAddr second_best_agent;
        int8_t next_best_rssi;
        int8_t second_best_rssi;
        uint8_t next_best_count;
        uint8_t second_best_count;
        bool move_in_progress;

        sVStaStats(const sMacAddr &Vbss_Id) : vbss_id(Vbss_Id)
        {
            next_best_rssi    = -120;
            second_best_rssi  = -120;
            next_best_count   = 0;
            second_best_count = 0;
            next_best_agent   = {};
            second_best_agent = {};
            move_in_progress  = false;
        }

        sVStaStats()
        {
            vbss_id           = {};
            next_best_rssi    = -120;
            second_best_rssi  = -120;
            next_best_count   = 0;
            second_best_count = 0;
            next_best_agent   = {};
            second_best_agent = {};
            move_in_progress  = false;
        }

        ~sVStaStats() {}
    };

    bool attempt_move_associated_client(const sMacAddr &agent_mac, const sMacAddr &cur_bssid,
                                        const sMacAddr &cl_mac);

    bool kickoff_associated_client_move(const sMacAddr &agent_mac, const sMacAddr &vbss_id,
                                        const sMacAddr &cl_mac);

    bool handle_vbss_for_associated_client(const sMacAddr &agent_mac, const sMacAddr &bssid);

    void control_all_by_nbapi(const bool &nbapi_active) { m_controlled_by_nbapi = nbapi_active; }

    bool is_nbapi_active() { return m_controlled_by_nbapi; }

    void set_legacy_steering_use(const bool &use_legacy) { m_use_legacy_steering = use_legacy; }

    bool use_legacy_steering() { return m_use_legacy_steering; }

    void set_last_sent_mid_unassoc(const uint16_t &mid) { last_sent_unassociated_mid = mid; }

    uint16_t get_last_sent_mid() { return last_sent_unassociated_mid; }

protected:
    bool find_available_vbssid(const sMacAddr &radio_mac, sMacAddr &nVbss_id);

    bool can_system_have_another_vbss();

    /**
     * @brief Registers this station to get rssi values from agents it's not associated to
     * 
     * @param client_mac 
     * @return true 
     * @return false 
     */
    bool register_client_for_rssi(const vbss::sStationConnectedEvent &stationConnect);

private:
    struct sOpenVbssStatus {
        sMacAddr vbss_id;
        bool create_sent;
        bool create_success;
        sOpenVbssStatus() {}
        ~sOpenVbssStatus() {}
    };
    /*
    * @brief This method will run on a frequency that's predfined and will make sure each 
    *           vsta and vbss combination is being hosted on the best client as determined
    *           by rssi values currently
    *           
    * @return No return value
    */
    void analyze_clients();

    // Timer value for how often to analyze clients
    const std::chrono::milliseconds ANALYZE_VSTA_VBSS{1000};

    //database object
    son::db &m_database;

    /*
    * Timer manager for running the process to varify vsta are having the best connections
    */
    std::shared_ptr<beerocks::TimerManager> m_timer_manager;

    int m_client_analysis_timer = {beerocks::net::FileDescriptor::invalid_descriptor};

    // Keep list of agents we received capabilities from so we don't bombard with requests
    // Perhaps later add a timestamp
    std::unordered_map<sMacAddr, bool> m_radio_vbss_capable_received;

    std::vector<std::string> m_unused_ssid_extensions;

    std::vector<std::string> m_used_ssid_extensions;

    std::unordered_map<sMacAddr, sMacAddr> m_client_agent;

    std::unordered_map<sMacAddr, bool> m_global_vbssid_map;

    std::unordered_map<sMacAddr, vbss::VbssManager::sOpenVbssStatus> m_open_vbsses;

    std::unordered_map<sMacAddr, sVStaStats> m_vsta_stats;

    std::vector<sMacAddr> m_cur_move_vbssid;

    uint16_t last_sent_unassociated_mid;

    // Save for later for possible better performance
    //std::unordered_map<uint8_t, std::list<sMacAddr>> m_channel_to_sta_map;

    //beerocks::mac_map<sMacAddr> m_pre_associated_clients;
    // I don't need a shared_pointer for this...
    std::unordered_map<sMacAddr, sMacAddr> m_pre_associated_clients;

    // Turn internal automated logic
    bool m_controlled_by_nbapi;
    // Use legacy steering
    // WARNING: Have not had successful results
    bool m_use_legacy_steering;
};

} // namespace vbss

#endif //VBSS_MANAGER_H
