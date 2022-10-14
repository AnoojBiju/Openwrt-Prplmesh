/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "base_wlan_hal_whm.h"

#include "ambiorix_client_factory.h"

#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_wireless_utils.h>

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <easylogging++.h>

namespace bwl {
namespace whm {

base_wlan_hal_whm::base_wlan_hal_whm(HALType type, const std::string &iface_name,
                                     hal_event_cb_t callback, const hal_conf_t &hal_conf)
    : base_wlan_hal(type, iface_name, IfaceType::Intel, callback, hal_conf),
      beerocks::beerocks_fsm<whm_fsm_state, whm_fsm_event>(whm_fsm_state::Delay)
{
    m_ambiorix_cl = beerocks::wbapi::AmbiorixClientFactory::create_instance();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client instance!";

    int amx_fd = m_ambiorix_cl->get_fd();
    if (amx_fd == -1) {
        LOG(FATAL) << "Failed opening amx fd, errno: " << strerror(errno);
    }

    int amxp_fd = m_ambiorix_cl->get_signal_fd();
    if (amxp_fd == -1) {
        LOG(FATAL) << "Failed opening amxp fd, errno: " << strerror(errno);
    }

    m_fds_ext_events = {amx_fd, amxp_fd};

    // Initialize the FSM
    fsm_setup();
}

base_wlan_hal_whm::~base_wlan_hal_whm()
{
    // Close the events FIFO
    if (m_fds_ext_events[0] != -1) {
        close(m_fds_ext_events[0]);
        m_fds_ext_events[0] = -1;
    }
    if (m_fds_ext_events[1] != -1) {
        close(m_fds_ext_events[1]);
        m_fds_ext_events[1] = -1;
    }

    base_wlan_hal_whm::detach();
}

bool base_wlan_hal_whm::fsm_setup() { return true; }

HALState base_wlan_hal_whm::attach(bool block)
{
    m_radio_info.radio_state = eRadioState::ENABLED;
    refresh_radio_info();
    return (m_hal_state = HALState::Operational);
}

bool base_wlan_hal_whm::detach() { return true; }

bool base_wlan_hal_whm::set(const std::string &param, const std::string &value, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool base_wlan_hal_whm::ping() { return true; }

bool base_wlan_hal_whm::refresh_radio_info()
{
    std::string wifi_radio_path;
    if (!whm_get_radio_path(get_iface_name(), wifi_radio_path)) {
        return false;
    }

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return false;
    }
    m_radio_info.tx_power = GET_UINT32(radio_obj, "TransmitPower");
    const char *op_band   = GET_CHAR(radio_obj, "CurrentOperatingChannelBandwidth");
    beerocks::eWiFiBandwidth band =
        beerocks::wbapi::wbapi_utils::bandwith_from_string(std::string(op_band));
    m_radio_info.bandwidth         = beerocks::utils::convert_bandwidth_to_int(band);
    m_radio_info.wifi_ctrl_enabled = GET_UINT32(radio_obj, "Enable");
    m_radio_info.channel           = GET_UINT32(radio_obj, "Channel");
    m_radio_info.is_5ghz =
        (son::wireless_utils::which_freq(m_radio_info.channel) == beerocks::eFreqType::FREQ_5G);

    const char *radio_status = GET_CHAR(radio_obj, "Status");
    m_radio_info.radio_state =
        utils_wlan_hal_whm::radio_state_from_string(std::string(radio_status));
    if (m_radio_info.radio_state == eRadioState::ENABLED) {
        m_radio_info.wifi_ctrl_enabled = 2; // Assume Operational
        m_radio_info.tx_enabled        = 1;
    }
    amxc_var_delete(&radio_obj);
    amxc_var_t *radio_driver_obj = m_ambiorix_cl->get_object(wifi_radio_path + "DriverStatus.", 0);
    if (!radio_driver_obj) {
        LOG(ERROR) << "failed to get radio DriverStatus object";
    } else {
        m_radio_info.ant_num = GET_UINT32(radio_driver_obj, "NrTxAntenna");
        amxc_var_delete(&radio_driver_obj);
    }

    if (!m_radio_info.available_vaps.size()) {
        if (!refresh_vaps_info(beerocks::IFACE_RADIO_ID)) {
            return false;
        }
    }

    return true;
}

amxc_var_t *base_wlan_hal_whm::get_radio_vaps()
{
    std::string search_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                              std::string(AMX_CL_RADIO_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                              "[Name == '" + m_radio_info.iface_name + "']" + AMX_CL_OBJ_DELIMITER +
                              "OperatingFrequencyBand";

    std::string radio_obj_path = "";
    amxc_var_t *radios_obj     = m_ambiorix_cl->get_object(search_path, 1);
    amxc_var_for_each(radio_obj, radios_obj)
    {
        const char *key = amxc_var_key(amxc_var_get_first(radio_obj));
        if (!key)
            continue;
        radio_obj_path.assign(amxc_var_key(radio_obj));
        break;
    }
    amxc_var_delete(&radios_obj);
    if (radio_obj_path.empty()) {
        LOG(ERROR) << "failed to get radio object path";
        return nullptr;
    }

    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 1);
    amxc_var_for_each(ap, aps)
    {
        bool match      = false;
        const char *key = GET_CHAR(ap, "RadioReference");
        if (key && key[0]) {
            radios_obj = m_ambiorix_cl->get_object(std::string(key) + ".Name", 1);
            amxc_var_for_each(radio_obj, radios_obj)
            {
                key = amxc_var_key(amxc_var_get_first(radio_obj));
                if (!key)
                    continue;
                if (amxc_var_key(radio_obj) == radio_obj_path) {
                    match = true;
                    break;
                }
            }
            amxc_var_delete(&radios_obj);
        }
        if (match) {
            LOG(DEBUG) << "Found vap " << amxc_var_key(ap) << " of rad " << radio_obj_path;
            continue;
        }
        amxc_var_take_it(ap);
        amxc_var_clean(ap);
    }
    return aps;
}

bool base_wlan_hal_whm::refresh_vaps_info(int id)
{
    bool ret        = false;
    amxc_var_t *aps = get_radio_vaps();
    int vap_id      = -1;
    amxc_var_for_each(ap, aps)
    {
        vap_id++;
        if (id == beerocks::IFACE_RADIO_ID || id == vap_id) {
            ret |= refresh_vap_info(vap_id, ap);
        }
        if (id == vap_id) {
            break;
        }
    }
    amxc_var_delete(&aps);
    return ret;
}

bool base_wlan_hal_whm::refresh_vap_info(int id, amxc_var_t *ap_obj)
{
    LOG(TRACE) << __func__ << " - id = " << id;

    VAPElement vap_element;
    const char *ssidRef = GET_CHAR(ap_obj, "SSIDReference");
    const char *ifname  = GET_CHAR(ap_obj, "Alias");
    if (ssidRef && ifname) {
        std::string wifi_ssid_path = std::string(ssidRef) + AMX_CL_OBJ_DELIMITER;

        amxc_var_t *ssid_obj = m_ambiorix_cl->get_object(wifi_ssid_path, 0);
        if (!ssid_obj) {
            LOG(ERROR) << "failed to get ssid object";
        } else {
            vap_element.bss  = ifname;
            vap_element.mac  = GET_CHAR(ssid_obj, "MACAddress");
            vap_element.ssid = GET_CHAR(ssid_obj, "SSID");
            amxc_var_delete(&ssid_obj);
            vap_element.fronthaul     = false;
            vap_element.backhaul      = false;
            const char *multi_ap_type = GET_CHAR(ap_obj, "MultiAPType");
            if (multi_ap_type) {
                std::string multi_ap_type_str = std::string(multi_ap_type);
                if (multi_ap_type_str.find("FronthaulBSS") != std::string::npos) {
                    vap_element.fronthaul = true;
                }
                if (multi_ap_type_str.find("BackhaulBSS") != std::string::npos) {
                    vap_element.backhaul = true;
                }
            }
        }
    }

    // VAP does not exists
    if (vap_element.mac.empty()) {
        if (m_radio_info.available_vaps.find(id) != m_radio_info.available_vaps.end()) {
            m_radio_info.available_vaps.erase(id);
        }

        return false;
    }

    // Store the VAP element
    LOG(WARNING) << "Detected VAP id (" << id << ") - MAC: " << vap_element.mac
                 << ", SSID: " << vap_element.ssid << ", BSS: " << vap_element.bss;

    auto &mapped_vap_element = m_radio_info.available_vaps[id];
    if (mapped_vap_element.bss.empty()) {
        LOG(WARNING) << "BSS " << vap_element.bss << " is not preconfigured!"
                     << "Overriding VAP element.";

        mapped_vap_element = vap_element;
        return true;

    } else if (mapped_vap_element.bss != vap_element.bss) {
        LOG(ERROR) << "bss mismatch! vap_element.bss=" << vap_element.bss
                   << ", mapped_vap_element.bss=" << mapped_vap_element.bss;
        return false;
    } else if (mapped_vap_element.ssid != vap_element.ssid) {
        LOG(DEBUG) << "SSID changed from " << mapped_vap_element.ssid << ", to " << vap_element.ssid
                   << ". Overriding VAP element.";
        mapped_vap_element = vap_element;
        return true;
    }

    mapped_vap_element.mac = vap_element.mac;

    return true;
}

bool base_wlan_hal_whm::process_ext_events(int fd)
{
    if (m_fds_ext_events[0] == fd) {
        m_ambiorix_cl->read();
    } else if (m_fds_ext_events[1] == fd) {
        m_ambiorix_cl->read_signal();
    }
    return true;
}

amxc_var_t *base_wlan_hal_whm::whm_get_wifi_ap_object(const std::string &iface)
{
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + "[Alias == '" +
                          iface + "']" + AMX_CL_OBJ_DELIMITER;
    return m_ambiorix_cl->get_object(ap_path, 0);
}

amxc_var_t *base_wlan_hal_whm::whm_get_wifi_ssid_object(const std::string &iface)
{
    // pwhm dm path: WiFi.SSID.[ Alias == 'iface' ].?
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_SSID_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + "[Alias == '" +
                          iface + "']" + AMX_CL_OBJ_DELIMITER;
    return m_ambiorix_cl->get_object(ap_path, 0);
}

int base_wlan_hal_whm::whm_get_vap_id(const std::string &iface)
{
    int vap_id = 0;
    std::string radioRef;
    if (whm_get_radio_ref(iface, radioRef)) {
        std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                              std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                              "[RadioReference == '" + radioRef + "']" + AMX_CL_OBJ_DELIMITER +
                              "Alias";
        int cnt         = -1;
        amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 1);
        amxc_var_for_each(ap, aps)
        {
            const char *ifname = GET_CHAR(ap, "Alias");
            if (!ifname || !ifname[0]) {
                continue;
            }
            cnt++;
            if (iface == ifname) {
                vap_id = cnt;
                break;
            }
        }
        amxc_var_delete(&aps);
    }
    return vap_id;
}

bool base_wlan_hal_whm::whm_get_radio_ref(const std::string &iface, std::string &ref)
{
    ref                = "";
    amxc_var_t *ap_obj = whm_get_wifi_ap_object(iface);
    if (!ap_obj) {
        LOG(ERROR) << "failed to get ap object";
        return false;
    }
    std::string ref_val = GET_CHAR(ap_obj, "RadioReference");
    amxc_var_delete(&ap_obj);
    if (ref_val.empty()) {
        LOG(ERROR) << "No radioReference for iface " << iface;
        return false;
    }
    ref = ref_val;
    return true;
}

bool base_wlan_hal_whm::whm_get_radio_path(const std::string &iface, std::string &path)
{
    bool ret = whm_get_radio_ref(iface, path);
    if (ret) {
        path += ".";
    }
    return ret;
}

std::string base_wlan_hal_whm::get_radio_mac()
{
    std::string mac;
    std::string wifi_radio_path;
    if (!whm_get_radio_path(get_iface_name(), wifi_radio_path)) {
        return mac;
    }

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return mac;
    }

    mac.assign(GET_CHAR(radio_obj, "BaseMACAddress"));
    amxc_var_delete(&radio_obj);
    return mac;
}

std::string base_wlan_hal_whm::whm_get_vap_instance_name(const std::string &iface)
{
    // pwhm dm path: WiFi.SSID.[ Alias == 'iface' ].Name?
    std::string vap_name = "";
    amxc_var_t *ssid_obj = whm_get_wifi_ssid_object(iface);
    if (!ssid_obj) {
        LOG(ERROR) << "failed to get ssid object";
        return vap_name;
    }
    const char *name = GET_CHAR(ssid_obj, "Name");
    if (name) {
        vap_name = std::string(name);
    }
    amxc_var_delete(&ssid_obj);
    return vap_name;
}

bool base_wlan_hal_whm::get_channel_utilization(uint8_t &channel_utilization)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

} // namespace whm
} // namespace bwl
