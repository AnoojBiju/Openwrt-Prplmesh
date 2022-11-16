//
// Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//
#include "./db/db.h"
#include "../../../vbss/vbss_core.h"

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
    VbssManager(son::db &db, std::shared_ptr<beerocks::TimerManager> timer_manager);

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

    /// @brief Analyze if radio can support vbss along with another client; to see if moving to vbss is possible
    /// @param agent_mac
    /// @param bssid
    /// @return true if possible to move; false if radio agent couldn't support the vbss operation
    bool can_radio_support_another_vbss(const sMacAddr &agent_mac, const sMacAddr &bssid);

    bool attempt_move_associated_client(const sMacAddr &agent_mac, const sMacAddr &cur_bssid,
                                        const sMacAddr &cl_mac);

    bool kickoff_associated_client_move(const sMacAddr &agent_mac, const sMacAddr &vbss_id,
                                        const sMacAddr &cl_mac);

    bool handle_vbss_for_associated_client(const sMacAddr &agent_mac, const sMacAddr &bssid);

protected:
    bool find_available_vbssid(const sMacAddr &radio_mac, sMacAddr &nVbss_id);

private:
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

    //beerocks::mac_map<sMacAddr> m_pre_associated_clients;
    // I don't need a shared_pointer for this...
    std::unordered_map<sMacAddr, sMacAddr> m_pre_associated_clients;
};

} // namespace vbss

#endif //VBSS_MANAGER_H
