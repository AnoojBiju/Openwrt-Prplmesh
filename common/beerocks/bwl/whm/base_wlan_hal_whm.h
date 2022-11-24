/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_BASE_WLAN_HAL_WHM_H_
#define _BWL_BASE_WLAN_HAL_WHM_H_

#include "utils_wlan_hal_whm.h"
#include <bcl/beerocks_state_machine.h>
#include <bwl/base_wlan_hal.h>
#include <bwl/nl80211_client.h>

#include "ambiorix_client.h"
#include "wbapi_utils.h"

#include <chrono>
#include <memory>

namespace bwl {
namespace whm {

enum class whm_fsm_state { Delay, Init, GetRadioInfo, Attach, Operational, Detach };

enum class whm_fsm_event { Attach, Detach };

struct VAPExtInfo {
    std::string path;
    std::string ssid_path;
    std::string status;
    bool teardown = false;

    bool operator==(const VAPExtInfo &other) const { return (path == other.path); }

    bool operator!=(const VAPExtInfo &other) const { return !(*this == other); }
};

struct STAExtInfo {
    std::string path;

    bool operator==(const STAExtInfo &other) const { return (path == other.path); }

    bool operator!=(const STAExtInfo &other) const { return !(*this == other); }
};

/*!
 * Base class for the whm abstraction layer.
 */
class base_wlan_hal_whm : public virtual base_wlan_hal,
                          protected beerocks::beerocks_fsm<whm_fsm_state, whm_fsm_event> {

    // Public methods:
public:
    virtual ~base_wlan_hal_whm();

    virtual HALState attach(bool block = false) override;
    virtual bool detach() override;
    virtual bool ping() override;
    virtual bool refresh_radio_info() override;
    virtual bool refresh_vaps_info(int id) override;
    virtual bool process_ext_events(int fd = 0) override;
    virtual bool process_nl_events() override { return true; };
    virtual std::string get_radio_mac() override;
    /**
     * @brief Gets channel utilization.
     *
     * @see base_wlan_hal::get_channel_utilization
     *
     * Returns a fake channel utilization value, varying from 0 to UINT8_MAX on each call.
     *
     * @param[out] channel_utilization Channel utilization value.
     *
     * @return True on success and false otherwise.
     */
    bool get_channel_utilization(uint8_t &channel_utilization) override;

    // Protected methods
protected:
    base_wlan_hal_whm(HALType type, const std::string &iface_name, hal_event_cb_t callback,
                      const hal_conf_t &hal_conf = {});

    virtual bool set(const std::string &param, const std::string &value,
                     int vap_id = beerocks::IFACE_RADIO_ID) override;
    int whm_get_vap_id(const std::string &iface);
    bool whm_get_radio_ref(const std::string &iface, std::string &ref);
    bool whm_get_radio_path(const std::string &iface, std::string &path);
    bool refresh_vap_info(int id, const beerocks::wbapi::AmbiorixVariant &ap_obj);
    bool get_radio_vaps(beerocks::wbapi::AmbiorixVariantList &aps);
    bool has_enabled_vap() const;
    bool check_enabled_vap(const std::string &bss) const;

    std::shared_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl;
    std::unique_ptr<nl80211_client> m_iso_nl80211_client; //impl nl80211 client apis with whm dm
    std::string m_radio_path;
    std::unordered_map<std::string, VAPExtInfo> m_vapsExtInfo; // key = vap_ifname
    std::unordered_map<std::string, STAExtInfo> m_stations;    // key = sta_mac
    void subscribe_to_radio_events();
    void subscribe_to_ap_events();
    void subscribe_to_sta_events();
    void subscribe_to_ep_events();
    void subscribe_to_ep_wps_events();
    virtual bool process_radio_event(const std::string &interface, const std::string &key,
                                     const beerocks::wbapi::AmbiorixVariant *value);
    virtual bool process_ap_event(const std::string &interface, const std::string &key,
                                  const beerocks::wbapi::AmbiorixVariant *value);
    virtual bool process_sta_event(const std::string &interface, const std::string &sta_mac,
                                   const std::string &key,
                                   const beerocks::wbapi::AmbiorixVariant *value);
    virtual bool process_ep_event(const std::string &interface, const std::string &key,
                                  const beerocks::wbapi::AmbiorixVariant *value);
    virtual bool process_ep_wps_event(const std::string &interface,
                                      const beerocks::wbapi::AmbiorixVariant *data);

    // Private data-members:
private:
    bool fsm_setup();
};

} // namespace whm
} // namespace bwl

#endif // _BWL_BASE_WLAN_HAL_WHM_H_
