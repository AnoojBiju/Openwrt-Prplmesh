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

#include "ambiorix_client.h"
#include "wbapi_utils.h"

#include <chrono>
#include <memory>

namespace bwl {
namespace whm {

enum class whm_fsm_state { Delay, Init, GetRadioInfo, Attach, Operational, Detach };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *whm_fsm_state_str(whm_fsm_state enum_value) {
    switch (enum_value) {
    case whm_fsm_state::Delay:        return "whm_fsm_state::Delay";
    case whm_fsm_state::Init:         return "whm_fsm_state::Init";
    case whm_fsm_state::GetRadioInfo: return "whm_fsm_state::GetRadioInfo";
    case whm_fsm_state::Attach:       return "whm_fsm_state::Attach";
    case whm_fsm_state::Operational:  return "whm_fsm_state::Operational";
    case whm_fsm_state::Detach:       return "whm_fsm_state::Detach";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, whm_fsm_state value) { return out << whm_fsm_state_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class whm_fsm_event { Attach, Detach };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *whm_fsm_event_str(whm_fsm_event enum_value) {
    switch (enum_value) {
    case whm_fsm_event::Attach: return "whm_fsm_event::Attach";
    case whm_fsm_event::Detach: return "whm_fsm_event::Detach";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, whm_fsm_event value) { return out << whm_fsm_event_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

typedef std::unordered_map<std::string, std::string> parsed_obj_map_t;
typedef std::list<parsed_obj_map_t> parsed_obj_listed_map_t;

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
    bool refresh_vap_info(int id);
    std::string whm_get_vap_instance_name(const std::string &iface);

    // Protected methods
protected:
    base_wlan_hal_whm(HALType type, const std::string &iface_name, hal_event_cb_t callback,
                      const hal_conf_t &hal_conf = {});

    virtual bool set(const std::string &param, const std::string &value,
                     int vap_id = beerocks::IFACE_RADIO_ID) override;
    amxc_var_t *whm_get_wifi_ap_object(const std::string &iface);
    amxc_var_t *whm_get_wifi_ssid_object(const std::string &iface);
    int whm_get_vap_id(const std::string &iface);
    bool whm_get_radio_ref(const std::string &iface, std::string &ref);
    bool whm_get_radio_path(const std::string &iface, std::string &path);
    bool refresh_vap_info(int id, amxc_var_t *ap_obj);
    amxc_var_t *get_radio_vaps();

    std::shared_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl;

    // Private data-members:
private:
    bool fsm_setup();
};

} // namespace whm
} // namespace bwl

#endif // _BWL_BASE_WLAN_HAL_WHM_H_
