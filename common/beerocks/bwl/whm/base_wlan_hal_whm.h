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

enum class whm_fsm_event { Attach, Detach };

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

    // Protected methods
protected:
    base_wlan_hal_whm(HALType type, const std::string &iface_name, hal_event_cb_t callback,
                      const hal_conf_t &hal_conf = {});

    virtual bool set(const std::string &param, const std::string &value,
                     int vap_id = beerocks::IFACE_RADIO_ID) override;
    amxc_var_t *whm_get_ap_obj(const std::string &iface);
    amxc_var_t *whm_get_ap_obj(const std::string &iface, const int vap_id);
    bool whm_get_radio_ref(const std::string &iface, std::string &ref);

    std::shared_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl;

    // Private data-members:
private:
    bool fsm_setup();
};

} // namespace whm
} // namespace bwl

#endif // _BWL_BASE_WLAN_HAL_WHM_H_