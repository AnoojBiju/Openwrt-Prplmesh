/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "base_wlan_hal_whm.h"

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
    m_ambiorix_cl = std::make_shared<beerocks::wbapi::AmbiorixClient>();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client instance!";

    LOG_IF(!m_ambiorix_cl->connect(AMBIORIX_WBAPI_BACKEND_PATH, AMBIORIX_WBAPI_BUS_URI), FATAL)
        << "Unable to connect to the ambiorix backend!";

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
    if (!whm_get_radio_ref(get_iface_name(), wifi_radio_path)) {
        return false;
    }

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return false;
    }

    std::string radio_driver_path = wifi_radio_path + "DriverStatus.";
    amxc_var_t *radio_driver_obj  = m_ambiorix_cl->get_object(radio_driver_path, 0);
    if (!radio_driver_obj) {
        LOG(ERROR) << "failed to get radio DriverStatus object";
        return false;
    }

    m_radio_info.ant_num  = GET_UINT32(radio_driver_obj, "NrTxAntenna");
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
    } else {
        return true;
    }

    if (!m_radio_info.available_vaps.size()) {
        if (!refresh_vaps_info(beerocks::IFACE_RADIO_ID)) {
            return false;
        }
    }

    return true;
}

bool base_wlan_hal_whm::refresh_vaps_info(int id)
{
    if (id > beerocks::IFACE_RADIO_ID) {
        return refresh_vap_info(id);
    } else {
        std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                              std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
        amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 1);

        if (aps) {
            uint8_t count = 0;
            amxc_var_for_each(ap, aps)
            {
                const char *ifname = GET_CHAR(ap, "Alias");
                if (!ifname) {
                    continue;
                }
                if (std::string(ifname) != get_iface_name()) {
                    continue;
                }
                refresh_vap_info(count);
                count++;
            }
        }
        return true;
    }
}

bool base_wlan_hal_whm::refresh_vap_info(int id)
{
    LOG(TRACE) << __func__ << " - id = " << id;

    amxc_var_t *ap_obj = whm_get_ap_obj(get_iface_name(), id);
    if (!ap_obj) {
        LOG(ERROR) << "failed to get ap object";
        return false;
    }
    const char *ssid_ref_val = GET_CHAR(ap_obj, "SSIDReference");
    if (!ssid_ref_val) {
        LOG(ERROR) << "failed to get ap SSIDReference";
        return false;
    }

    std::string wifi_ssid_path = std::string(ssid_ref_val) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *ssid_obj       = m_ambiorix_cl->get_object(wifi_ssid_path, 0);
    if (!ssid_obj) {
        LOG(ERROR) << "failed to get ssid object";
        return false;
    }

    VAPElement vap_element;
    vap_element.bss  = GET_CHAR(ssid_obj, "Name");
    vap_element.mac  = GET_CHAR(ssid_obj, "MACAddress");
    vap_element.ssid = GET_CHAR(ssid_obj, "SSID");

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

amxc_var_t *base_wlan_hal_whm::whm_get_ap_obj(const std::string &iface)
{
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 2);

    if (aps) {
        amxc_var_for_each(ap, aps)
        {
            const char *ifname = GET_CHAR(ap, "Alias");
            if (!ifname) {
                continue;
            }
            if (std::string(ifname) != get_iface_name()) {
                continue;
            }
            return ap;
        }
    }

    return nullptr;
}

amxc_var_t *base_wlan_hal_whm::whm_get_ap_obj(const std::string &iface, const int vap_id)
{
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 2);

    if (aps) {
        uint8_t count = 0;
        amxc_var_for_each(ap, aps)
        {
            const char *ifname = GET_CHAR(ap, "Alias");
            if (!ifname) {
                continue;
            }
            if (std::string(ifname) != get_iface_name()) {
                continue;
            }
            if (vap_id == count) {
                return ap;
            }
            count++;
        }
    }
    return nullptr;
}

bool base_wlan_hal_whm::whm_get_radio_ref(const std::string &iface, std::string &ref)
{
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 2);

    if (aps) {
        amxc_var_for_each(ap, aps)
        {
            const char *ifname = GET_CHAR(ap, "Alias");
            if (!ifname) {
                continue;
            }
            if (std::string(ifname) == iface) {
                const char *ref_val = GET_CHAR(ap, "RadioReference");
                ref                 = std::string(ref_val) + ".";
                return true;
            }
        }
    }

    return false;
}

std::string base_wlan_hal_whm::get_radio_mac()
{
    std::string mac;
    std::string wifi_radio_path;
    if (!whm_get_radio_ref(get_iface_name(), wifi_radio_path)) {
        return mac;
    }

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return mac;
    }

    const char *base_mac = GET_CHAR(radio_obj, "BaseMACAddress");
    return std::string(base_mac);
}

bool base_wlan_hal_whm::get_channel_utilization(uint8_t &channel_utilization)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

} // namespace whm
} // namespace bwl
