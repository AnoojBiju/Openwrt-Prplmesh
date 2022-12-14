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

using namespace beerocks;
using namespace wbapi;

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

bool sta_wlan_hal_whm::scan_bss(const sMacAddr &bssid, uint8_t channel,
                                beerocks::eFreqType freq_type)
{
    return true;
}

int sta_wlan_hal_whm::get_scan_results(const std::string &ssid, std::vector<SScanResult> &list,
                                       bool parse_vsie)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return 0;
}

bool sta_wlan_hal_whm::connect(const std::string &ssid, const std::string &pass, WiFiSec sec,
                               bool mem_only_psk, const std::string &bssid, ChannelFreqPair channel,
                               bool hidden_ssid)
{
    LOG(DEBUG) << "Connect interface " << get_iface_name() << " to SSID = " << ssid
               << ", BSSID = " << bssid << ", Channel = " << int(channel.first)
               << ", freq type =" << channel.second << ", Sec = " << sec
               << ", mem_only_psk=" << int(mem_only_psk);

    if (ssid.empty() || sec == WiFiSec::Invalid) {
        LOG(ERROR) << "Invalid params!";
        return false;
    }

    // First disconnect (or do nothing if not connected)
    if (!disconnect()) {
        LOG(WARNING) << "Failed disconnecting before connecting to the new BSSID";
        return false;
    }

    // Add a new profile
    int profile_id = add_profile();
    if (profile_id < 0) {
        LOG(ERROR) << "Failed (" << profile_id
                   << ") adding new profile to interface: " << get_iface_name();
        return false;
    }

    // Update profile parameters
    if (!set_profile_params(profile_id, ssid, bssid, sec, mem_only_psk, pass, hidden_ssid,
                            channel.first)) {
        LOG(ERROR) << "Failed setting profile id = " << profile_id
                   << " on interface: " << get_iface_name();
        return false;
    }

    // Enable the profile
    if (!enable_profile(profile_id)) {
        LOG(ERROR) << "Failed enabling profile id = " << profile_id
                   << " on interface: " << get_iface_name();
        return false;
    }

    LOG(DEBUG) << "Profile with id " << profile_id << " has been added and enabled on interface "
               << get_iface_name();

    // Update active endpoint parameters
    m_active_ssid.assign(ssid);
    m_active_bssid.assign(bssid);
    m_active_pass.assign(pass);
    m_active_channel    = channel.first;
    m_active_profile_id = profile_id;

    return true;
}

bool sta_wlan_hal_whm::disconnect()
{
    LOG(TRACE) << "Disconnect profile id " << m_active_profile_id
               << " on interface: " << get_iface_name();

    Endpoint endpoint;
    if (!read_status(endpoint)) {
        LOG(ERROR) << "Failed reading status for " << get_iface_name() << "! can't disconnect";
        return false;
    }

    // Return gracefully if endpoint connection_status is not connected
    if (!is_connected(endpoint.connection_status)) {
        LOG(DEBUG) << "Active profile is not connected";
        return true;
    }

    // Return gracefully if no endpoint connection_status is connected
    if (m_active_profile_id < 0) {
        LOG(DEBUG) << "Active profile does not exist";
        return true;
    }

    // Connection status id must be the same as the active profile id
    if (m_active_profile_id != endpoint.active_profile_id) {
        LOG(ERROR) << "Profile id mismatch: m_active_profile_id(" << m_active_profile_id << ") != "
                   << "endpoint.active_profile_id(" << endpoint.active_profile_id << ")";
        return false;
    }

    if (remove_profile(m_active_profile_id)) {
        LOG(ERROR) << "Failed to disconnect profile " << m_active_profile_id;
        return false;
    }

    // Clear state
    m_active_ssid       = "";
    m_active_bssid      = "";
    m_active_pass       = "";
    m_active_channel    = 0;
    m_active_profile_id = -1;

    return true;
}

bool sta_wlan_hal_whm::roam(const sMacAddr &bssid, ChannelFreqPair channel) { return true; }

bool sta_wlan_hal_whm::get_4addr_mode() { return true; }

bool sta_wlan_hal_whm::set_4addr_mode(bool enable) { return true; }

bool sta_wlan_hal_whm::unassoc_rssi_measurement(const std::string &mac, int chan, int bw,
                                                int vht_center_frequency, int delay,
                                                int window_size)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool sta_wlan_hal_whm::reassociate()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool sta_wlan_hal_whm::is_connected()
{
    Endpoint endpoint;
    if (!read_status(endpoint)) {
        LOG(ERROR) << "Failed reading endpoint status for iface: " << get_iface_name();
        return false;
    }

    return is_connected(endpoint.connection_status);
}
int sta_wlan_hal_whm::get_channel() { return m_active_channel; }

std::string sta_wlan_hal_whm::get_ssid() { return m_active_ssid; }

std::string sta_wlan_hal_whm::get_bssid() { return m_active_bssid; }

bool sta_wlan_hal_whm::update_status()
{
    Endpoint endpoint;
    if (!read_status(endpoint)) {
        LOG(ERROR) << "Failed reading endpoint status for iface: " << get_iface_name();
        return false;
    }
    update_status(endpoint);

    return true;
}

int sta_wlan_hal_whm::add_profile()
{
    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].Profile+
    std::string profiles_path = wbapi_utils::search_path_ep_profiles_by_iface(get_iface_name());
    int profile_id            = -1;
    AmbiorixVariant obj_data(nullptr, false);
    bool ret = m_ambiorix_cl->add_instance(profiles_path, obj_data, profile_id);
    if (!ret) {
        LOG(ERROR) << "Failed to add profile instance " << get_iface_name();
    }
    return profile_id;
}

int sta_wlan_hal_whm::remove_profile(int profile_id)
{
    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].Profile+
    std::string profiles_path = wbapi_utils::search_path_ep_profiles_by_iface(get_iface_name());

    bool ret = m_ambiorix_cl->remove_instance(profiles_path, profile_id);
    if (!ret) {
        LOG(ERROR) << "Failed to remove profile instance with id:" << profile_id;
    }
    return profile_id;
}

bool sta_wlan_hal_whm::set_profile_params(int profile_id, const std::string &ssid,
                                          const std::string &bssid, WiFiSec sec, bool mem_only_psk,
                                          const std::string &pass, bool hidden_ssid, int channel)
{
    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].Profile.1.
    std::string profile_path =
        wbapi_utils::search_path_ep_profile_by_id(get_iface_name(), profile_id);
    AmbiorixVariant params(AMXC_VAR_ID_HTABLE);

    // Set SSID
    params.add_child<>("SSID", ssid);
    bool ret = m_ambiorix_cl->update_object(profile_path, params);
    if (!ret) {
        LOG(ERROR) << "Failed setting ssid on interface " << get_iface_name();
        return false;
    }

    // Set BSSID : optional
    if (!bssid.empty()) {
        params.set_type(AMXC_VAR_ID_HTABLE);
        params.add_child<>("ForceBSSID", bssid);
        ret = m_ambiorix_cl->update_object(profile_path, params);
        if (!ret) {
            LOG(ERROR) << "Failed setting bssid on interface " << get_iface_name();
            return false;
        }
    }

    // Optional: set channel : not supported by pwhm

    // Set Security
    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].Profile.1.Security.
    std::string profile_security_path = profile_path + "Security.";
    std::string mode_enabled          = utils_wlan_hal_whm::security_type_to_string(sec);
    params.set_type(AMXC_VAR_ID_HTABLE);
    params.add_child<>("ModeEnabled", mode_enabled);
    ret = m_ambiorix_cl->update_object(profile_security_path, params);
    if (!ret) {
        LOG(ERROR) << "Failed setting security on interface " << get_iface_name();
        return false;
    }

    // Optional: set hidden-ssid: not supported by pwhm

    // mem_only_psk not supported by pwhm

    // Set psk
    params.set_type(AMXC_VAR_ID_HTABLE);
    params.add_child<>("KeyPassPhrase", pass);
    ret = m_ambiorix_cl->update_object(profile_security_path, params);
    if (!ret) {
        LOG(ERROR) << "Failed setting security psk on interface " << get_iface_name();
        return false;
    }
    return true;
}

bool sta_wlan_hal_whm::enable_profile(int profile_id)
{
    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].Profile.1.
    std::string profile_path =
        wbapi_utils::search_path_ep_profile_by_id(get_iface_name(), profile_id);

    AmbiorixVariant params(AMXC_VAR_ID_HTABLE);
    params.add_child<bool>("Enable", true);
    bool ret = m_ambiorix_cl->update_object(profile_path, params);
    if (!ret) {
        LOG(ERROR) << "Failed to enable profile " << get_iface_name();
        return false;
    }

    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].
    std::string endpoint_path = wbapi_utils::search_path_ep_by_iface(get_iface_name());
    std::string profile_ref;
    m_ambiorix_cl->resolve_path(profile_path, profile_ref);
    params.set_type(AMXC_VAR_ID_HTABLE);
    params.add_child<>("ProfileReference", profile_ref);
    ret = m_ambiorix_cl->update_object(endpoint_path, params);
    if (!ret) {
        LOG(ERROR) << "Failed to set profile preference " << get_iface_name();
        return false;
    }
    return true;
}

bool sta_wlan_hal_whm::read_status(Endpoint &endpoint)
{
    // Path example: WiFi.EndPoint.[IntfName == 'wlan0'].
    std::string endpoint_path = wbapi_utils::search_path_ep_by_iface(get_iface_name());

    auto endpoint_obj = m_ambiorix_cl->get_object(endpoint_path);
    if (!endpoint_obj) {
        LOG(ERROR) << "failed to get endpoint object";
        return false;
    }

    endpoint_obj->read_child<>(endpoint.connection_status, "ConnectionStatus");

    std::string ssid_ref, ssid_path;
    if (endpoint_obj->read_child<>(ssid_ref, "SSIDReference") &&
        m_ambiorix_cl->resolve_path(ssid_ref + ".", ssid_path)) {
        auto ssid_obj = m_ambiorix_cl->get_object(ssid_path);
        if (!ssid_obj) {
            LOG(ERROR) << "failed to get ssid object";
            return false;
        }
        ssid_obj->read_child<>(endpoint.bssid, "BSSID");
        ssid_obj->read_child<>(endpoint.ssid, "SSID");
        std::string radio_path;
        if (ssid_obj->read_child<>(radio_path, "LowerLayers")) {
            m_radio_path = radio_path;
        }
        if (!m_ambiorix_cl->get_param<>(endpoint.channel, m_radio_path, "Channel")) {
            LOG(ERROR) << "failed to get radio channel from: " << m_radio_path;
            return false;
        }
    }

    std::string profile_ref, profile_path;
    if (endpoint_obj->read_child<>(profile_ref, "ProfileReference") &&
        m_ambiorix_cl->resolve_path(profile_ref + ".", profile_path)) {
        endpoint.active_profile_id = wbapi_utils::get_object_id(profile_path);
    }

    LOG(DEBUG) << "active profile " << m_active_profile_id;
    return true;
}

void sta_wlan_hal_whm::update_status(const Endpoint &endpoint)
{
    m_active_bssid      = endpoint.bssid;
    m_active_ssid       = endpoint.ssid;
    m_active_profile_id = endpoint.active_profile_id;
    m_active_channel    = endpoint.channel;

    LOG(DEBUG) << "m_active_profile_id= " << m_active_profile_id
               << ", active_bssid= " << m_active_bssid << ", active_channel= " << m_active_channel
               << ", active_ssid= " << m_active_ssid;
}

bool sta_wlan_hal_whm::is_connected(const std::string &status)
{
    return (status.compare("Connected") == 0);
}

} // namespace whm

std::shared_ptr<sta_wlan_hal> sta_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback,
                                                  const bwl::hal_conf_t &hal_conf)
{
    return std::make_shared<whm::sta_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
