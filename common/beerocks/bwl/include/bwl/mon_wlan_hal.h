/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_MON_WLAN_HAL_H_
#define _BWL_MON_WLAN_HAL_H_

#include "base_wlan_hal.h"
#include "mon_wlan_hal_types.h"
#include <vector>

namespace bwl {

/*!
  * Hardware abstraction layer for WLAN Monitor.
  * Read more about virtual inheritance: https://en.wikipedia.org/wiki/Virtual_inheritance
  */
class mon_wlan_hal : public virtual base_wlan_hal {

    // Public definitions
public:
    enum class Event {
        Invalid = 0,

        STA_Connected,
        STA_Disconnected,
        AP_Enabled,
        AP_Disabled,
        // RRM (802.11k) Events
        RRM_Channel_Load_Response,
        RRM_Beacon_Request_Status,
        RRM_Beacon_Response,
        //CHANNEL_SCAN events
        Channel_Scan_Triggered,
        Channel_Scan_New_Results_Ready,
        Channel_Scan_Dump_Result,
        Channel_Scan_Aborted,
        Channel_Scan_Finished,

        Interface_Connected_OK,
        Interface_Reconnected_OK,
        Interface_Disconnected
    };

    // Public methods:
public:
    virtual ~mon_wlan_hal() = default;

    virtual bool update_radio_stats(SRadioStats &radio_stats)                              = 0;
    virtual bool update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats) = 0;
    virtual bool update_stations_stats(const std::string &vap_iface_name,
                                       const std::string &sta_mac, SStaStats &sta_stats)   = 0;

    virtual bool sta_channel_load_11k_request(const SStaChannelLoadRequest11k &req)      = 0;
    virtual bool sta_beacon_11k_request(const SBeaconRequest11k &req, int &dialog_token) = 0;
    virtual bool sta_link_measurements_11k_request(const std::string &sta_mac)           = 0;
    virtual bool channel_scan_trigger(int dwell_time_msec,
                                      const std::vector<unsigned int> &channel_pool)     = 0;
    virtual bool channel_scan_dump_results()                                             = 0;
    /**
     * @brief Abort the in-progress channel scan for the interface
     *
     * @param[in] interface_name radio interface name.
     * 
     * @return true on success and false otherwise.
     */
    virtual bool channel_scan_abort() = 0;

    /**
     * @brief Generates client-connected event for already connected clients.
     * This is used to overcome a scenario where clients that are already connected
     * are not known to prplmesh and "missed" the "connected" event for them. This scenario
     * can happen due to prplmesh unexpected restart, son-slave unexpected restart and/or during development
     * when prplmesh is intentionally restarted.
     * 
     * @param [out] is_finished_all_clients - Is generation for all clients complete
     * @param [in] max_iteration_timeout - The time when thread awake time expires and function must return
     * 
     * @return true if finished generating, false otherwise
     */
    virtual bool generate_connected_clients_events(
        bool &is_finished_all_clients,
        const std::chrono::steady_clock::time_point max_iteration_timeout =
            std::chrono::steady_clock::time_point::max()) = 0;
};

// mon HAL factory types
std::shared_ptr<mon_wlan_hal> mon_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t cb,
                                                  const bwl::hal_conf_t &hal_conf);

} // namespace bwl

#endif // _BWL_MON_WLAN_HAL_H_
