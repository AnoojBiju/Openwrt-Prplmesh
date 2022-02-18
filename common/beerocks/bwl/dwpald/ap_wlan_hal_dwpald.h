/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_AP_WLAN_HAL_DWPALD_H_
#define _BWL_AP_WLAN_HAL_DWPALD_H_

#include "base_wlan_hal_dwpald.h"
#include <bcl/network/network_utils.h>

#include <bwl/ap_wlan_hal.h>

extern "C" {
#include <dwpal.h>
#include <dwpald_client.h>
}
namespace bwl {
namespace dwpal {

/*!
 * Hardware abstraction layer for WLAN Access Point.
 */
class ap_wlan_hal_dwpal : public base_wlan_hal_dwpal, public ap_wlan_hal {

    // Public methods
public:
    /*!
     * Constructor.
     *
     * @param [in] iface_name AP interface name.
     * @param [in] callback Callback for handling internal events.
     */
    ap_wlan_hal_dwpal(const std::string &iface_name, hal_event_cb_t callback,
                      const hal_conf_t &hal_conf);

    virtual ~ap_wlan_hal_dwpal();

    virtual HALState attach(bool block = false) override;
    bool refresh_radio_info() override;
    virtual bool enable() override;
    virtual bool disable() override;
    virtual bool set_start_disabled(bool enable, int vap_id = beerocks::IFACE_RADIO_ID) override;
    virtual bool
    set_channel(int chan, beerocks::eWiFiBandwidth bw = beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN,
                int center_channel = 0) override;
    virtual bool sta_allow(const std::string &mac, const std::string &bssid) override;
    virtual bool sta_deny(const std::string &mac, const std::string &bssid) override;
    virtual bool sta_disassoc(int8_t vap_id, const std::string &mac, uint32_t reason = 0) override;
    virtual bool sta_deauth(int8_t vap_id, const std::string &mac, uint32_t reason = 0) override;
    virtual bool sta_bss_steer(const std::string &mac, const std::string &bssid, int oper_class,
                               int chan, int disassoc_timer_btt, int valid_int_btt,
                               int reason) override;
    virtual bool
    update_vap_credentials(std::list<son::wireless_utils::sBssInfoConf> &bss_info_conf_list,
                           const std::string &backhaul_wps_ssid,
                           const std::string &backhaul_wps_passphrase) override;
    virtual bool sta_unassoc_rssi_measurement(const std::string &mac, int chan, int bw,
                                              int vht_center_frequency, int delay,
                                              int window_size) override;
    virtual bool sta_softblock_add(const std::string &vap_name, const std::string &client_mac,
                                   uint8_t reject_error_code, uint8_t probe_snr_threshold_hi,
                                   uint8_t probe_snr_threshold_lo,
                                   uint8_t authetication_snr_threshold_hi,
                                   uint8_t authetication_rsnr_threshold_lo) override;

    virtual bool sta_softblock_remove(const std::string &vap_name,
                                      const std::string &client_mac) override;
    virtual bool switch_channel(int chan, int bw, int vht_center_frequency) override;
    virtual bool cancel_cac(int chan, beerocks::eWiFiBandwidth bw, int vht_center_frequency,
                            int secondary_chan_offset) override;
    virtual bool failsafe_channel_set(int chan, int bw, int vht_center_frequency) override;
    virtual bool failsafe_channel_get(int &chan, int &bw) override;
    virtual bool is_zwdfs_supported() override;
    virtual bool set_zwdfs_antenna(bool enable) override;
    virtual bool is_zwdfs_antenna_enabled() override;
    virtual bool hybrid_mode_supported() override;
    virtual bool restricted_channels_set(char *channel_list) override;
    virtual bool restricted_channels_get(char *channel_list) override;
    virtual bool read_acs_report() override;
    virtual bool set_tx_power_limit(int tx_pow_limit) override;
    virtual bool set_vap_enable(const std::string &iface_name, const bool enable) override;
    virtual bool get_vap_enable(const std::string &iface_name, bool &enable) override;

    virtual void hostap_attach(char *ifname) override;
    /**
     * @brief Generates connected events for already connected clients.
     *
     * @see ap_wlan_hal::generate_connected_clients_events
     */
    virtual bool generate_connected_clients_events(
        bool &is_finished_all_clients,
        const std::chrono::steady_clock::time_point max_iteration_timeout =
            std::chrono::steady_clock::time_point::max()) override;

    /**
     * @brief Clear progress of generate-connected-clients-events.
     * 
     * @see ap_wlan_hal::pre_generate_connected_clients_events
     */
    virtual bool pre_generate_connected_clients_events() override;

    virtual bool start_wps_pbc() override;
    virtual bool set_mbo_assoc_disallow(const std::string &bssid, bool enable) override;
    virtual bool set_radio_mbo_assoc_disallow(bool enable) override;
    virtual bool set_primary_vlan_id(uint16_t primary_vlan_id) override;
    int filter_bss_msg(char *buffer, int bufLen, const std::string &opcode);
    virtual int hap_evt_interface_disabled_clb(char *ifname, char *op_code, char *msg,
                                               size_t len) override;
    virtual int hap_evt_acs_completed_clb(char *ifname, char *op_code, char *msg,
                                          size_t len) override;
    virtual int hap_evt_ap_csa_finished_clb(char *ifname, char *op_code, char *msg,
                                            size_t len) override;
    virtual int hap_evt_acs_failed_clb(char *ifname, char *op_code, char *msg, size_t len) override;
    virtual int hap_evt_ap_sta_connected_clb(char *ifname, char *op_code, char *msg,
                                             size_t len) override;
    virtual int hap_evt_ap_sta_disconnected_clb(char *ifname, char *op_code, char *msg,
                                                size_t len) override;
    virtual int hap_evt_unconnected_sta_rssi_clb(char *ifname, char *op_code, char *msg,
                                                 size_t len) override;
    virtual int hap_evt_ltq_softblock_drop_clb(char *ifname, char *op_code, char *msg,
                                               size_t len) override;
    virtual int hap_evt_bss_tm_query_clb(char *ifname, char *op_code, char *msg,
                                         size_t len) override;
    virtual int hap_evt_bss_tm_resp_clb(char *ifname, char *op_code, char *msg,
                                        size_t len) override;
    virtual int hap_evt_dfs_cac_start_clb(char *ifname, char *op_code, char *msg,
                                          size_t len) override;
    virtual int hap_evt_dfs_cac_completed_clb(char *ifname, char *op_code, char *msg,
                                              size_t len) override;
    virtual int hap_evt_dfs_nop_finished_clb(char *ifname, char *op_code, char *msg,
                                             size_t len) override;
    virtual int hap_evt_ap_disabled_clb(char *ifname, char *op_code, char *msg,
                                        size_t len) override;
    virtual int hap_evt_ap_enabled_clb(char *ifname, char *op_code, char *msg, size_t len) override;
    virtual int hap_evt_ap_action_frame_received_clb(char *ifname, char *op_code, char *msg,
                                                     size_t len) override;
    virtual int hap_evt_ap_sta_possible_psk_mismatch_clb(char *ifname, char *op_code, char *msg,
                                                         size_t len) override;

#if 0
    virtual int hap_evt_interface_enabled_clb(char *ifname, char *op_code, char *msg, size_t len) override;
    virtual int hap_evt_acs_started_clb(char *ifname, char *op_code, char *msg, size_t len) override;
#endif
    std::chrono::steady_clock::time_point &get_csa_event_filtering_timestamp()
    {
        return m_csa_event_filtering_timestamp;
    }
    bool &get_drop_csa() { return m_drop_csa; }
    std::set<int> &get_completed_vap() { return m_completed_vaps; }
    std::unordered_set<sMacAddr> &get_handled_clients() { return m_handled_clients; }
    std::chrono::steady_clock::time_point &get_unassoc_measure_start()
    {
        return m_unassoc_measure_start;
    }
    int &get_unassoc_measure_window_size() { return m_unassoc_measure_window_size; }
    int &get_unassoc_measure_delay() { return m_unassoc_measure_delay; }
    
    int get_ext_events_write_fd()
    {
        return m_pfd[1];
    }
    
    std::string get_status_dir(const std::string &filename = {}) const
    {
        return std::string(BEEROCKS_TMP_PATH) + "/" + get_iface_name() +
               (!filename.empty() ? "/" + filename : "");
    }
    // Protected methods:
protected:
    virtual bool process_dwpal_event(char *buffer, int bufLen, const std::string &opcode) override;
    virtual bool process_dwpal_nl_event(struct nl_msg *msg, void *arg = nullptr) override;

    // Overload for AP events
    bool event_queue_push(ap_wlan_hal::Event event, std::shared_ptr<void> data = {})
    {
        return base_wlan_hal::event_queue_push(int(event), data);
    }


private:
    bool set_wifi_bw(beerocks::eWiFiBandwidth);

    bool set_multiap_wps(std::map<std::string, std::vector<std::string>> &hostapd_config_vaps);
    // Unassociated measurement state variables
    std::chrono::steady_clock::time_point m_unassoc_measure_start;
    int m_unassoc_measure_window_size = 0;
    int m_unassoc_measure_delay       = 0;

    bool m_drop_csa = false;
    std::chrono::steady_clock::time_point m_csa_event_filtering_timestamp;

    static constexpr int INVALID_VAP_ID = -1;

    std::set<int> m_completed_vaps;
    std::unordered_set<sMacAddr> m_handled_clients;
    sMacAddr m_prev_client_mac = beerocks::net::network_utils::ZERO_MAC;
    bool m_queried_first       = false;
    int m_vap_id_in_progress   = INVALID_VAP_ID;
    std::string m_dummy_event_file;
    int m_pfd[2];
};

} // namespace dwpal
} // namespace bwl

#endif // _BWL_AP_WLAN_HAL_DWPALD_H_
