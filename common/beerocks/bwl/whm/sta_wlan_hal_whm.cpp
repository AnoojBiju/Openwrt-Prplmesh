/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "sta_wlan_hal_whm.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

#include <easylogging++.h>

namespace bwl {
namespace whm {

sta_wlan_hal_whm::sta_wlan_hal_whm(const std::string &iface_name, hal_event_cb_t callback,
                                   const bwl::hal_conf_t &hal_conf)
    : base_wlan_hal(bwl::HALType::Station, iface_name, IfaceType::Intel, callback, hal_conf),
      base_wlan_hal_whm(bwl::HALType::Station, iface_name, callback, hal_conf)
{
}

sta_wlan_hal_whm::~sta_wlan_hal_whm() { sta_wlan_hal_whm::detach(); }

bool sta_wlan_hal_whm::start_wps_pbc()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool sta_wlan_hal_whm::detach() { return true; }

bool sta_wlan_hal_whm::initiate_scan() { return true; }

bool sta_wlan_hal_whm::scan_bss(const sMacAddr &bssid, uint8_t channel) { return true; }

int sta_wlan_hal_whm::get_scan_results(const std::string &ssid, std::vector<SScanResult> &list,
                                       bool parse_vsie)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return 0;
}

bool sta_wlan_hal_whm::connect(const std::string &ssid, const std::string &pass, WiFiSec sec,
                               bool mem_only_psk, const std::string &bssid, uint8_t channel,
                               bool hidden_ssid)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool sta_wlan_hal_whm::disconnect() { return true; }

bool sta_wlan_hal_whm::roam(const sMacAddr &bssid, uint8_t channel) { return true; }

bool sta_wlan_hal_whm::get_4addr_mode() { return true; }

bool sta_wlan_hal_whm::set_4addr_mode(bool enable) { return true; }

bool sta_wlan_hal_whm::unassoc_rssi_measurement(const std::string &mac, int chan, int bw,
                                                int vht_center_frequency, int delay,
                                                int window_size)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool sta_wlan_hal_whm::is_connected()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}
int sta_wlan_hal_whm::get_channel() { return m_active_channel; }

std::string sta_wlan_hal_whm::get_ssid() { return m_active_ssid; }

std::string sta_wlan_hal_whm::get_bssid() { return m_active_bssid; }

bool sta_wlan_hal_whm::process_whm_event(sta_wlan_hal::Event event, const amxc_var_t *data)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool sta_wlan_hal_whm::update_status()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

} // namespace whm

std::shared_ptr<sta_wlan_hal> sta_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback,
                                                  const bwl::hal_conf_t &hal_conf)
{
    return std::make_shared<whm::sta_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
