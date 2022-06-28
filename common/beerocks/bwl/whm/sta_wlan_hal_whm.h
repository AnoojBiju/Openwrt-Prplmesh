/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_STA_WLAN_HAL_WHM_H_
#define _BWL_STA_WLAN_HAL_WHM_H_

#include "base_wlan_hal_whm.h"
#include <bwl/sta_wlan_hal.h>

namespace bwl {
namespace whm {

/*!
 * Hardware abstraction layer for WLAN Station/Client.
 */
class sta_wlan_hal_whm : public base_wlan_hal_whm, public sta_wlan_hal {

    // Public methods
public:
    /*!
     * Constructor.
     *
     * @param [in] iface_name STA/Client interface name.
     * @param [in] callback Callback for handling internal events.
     */
    sta_wlan_hal_whm(const std::string &iface_name, hal_event_cb_t callback,
                     const bwl::hal_conf_t &hal_conf);
    virtual ~sta_wlan_hal_whm();

    virtual bool start_wps_pbc() override;
    virtual bool detach() override;

    virtual bool initiate_scan() override;
    bool scan_bss(const sMacAddr &bssid, uint8_t channel) override;
    virtual int get_scan_results(const std::string &ssid, std::vector<SScanResult> &list,
                                 bool parse_vsie = false) override;

    virtual bool connect(const std::string &ssid, const std::string &pass, WiFiSec sec,
                         bool mem_only_psk, const std::string &bssid, uint8_t channel,
                         bool hidden_ssid) override;

    virtual bool disconnect() override;

    virtual bool roam(const sMacAddr &bssid, uint8_t channel) override;

    virtual bool get_4addr_mode() override;
    virtual bool set_4addr_mode(bool enable) override;

    virtual bool unassoc_rssi_measurement(const std::string &mac, int chan, int bw,
                                          int vht_center_frequency, int delay,
                                          int window_size) override;

    virtual bool is_connected() override;
    virtual int get_channel() override;
    virtual bool update_status() override;

    std::string get_ssid() override;
    std::string get_bssid() override;

protected:
    // Overload for Monitor events
    bool event_queue_push(sta_wlan_hal::Event event, std::shared_ptr<void> data = {})
    {
        return base_wlan_hal::event_queue_push(int(event), data);
    }

private:
    bool process_whm_event(sta_wlan_hal::Event event, const amxc_var_t *data);
    // Active network parameters
    std::string m_active_ssid;
    std::string m_active_bssid;
    uint8_t m_active_channel = 0;
};

} // namespace whm
} // namespace bwl

#endif // _BWL_STA_WLAN_HAL_WHM_H_