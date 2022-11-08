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
      beerocks::beerocks_fsm<whm_fsm_state, whm_fsm_event>(whm_fsm_state::Delay), wbapi_utils()
{
    m_ambiorix_cl = beerocks::wbapi::AmbiorixClientFactory::create_instance();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client instance!";

    int amx_fd = m_ambiorix_cl->get_fd();
    LOG_IF((amx_fd == -1), FATAL) << "Failed opening amx fd, errno: " << strerror(errno);

    int amxp_fd = m_ambiorix_cl->get_signal_fd();
    if (amxp_fd == -1) {
        LOG(FATAL) << "Failed opening amxp fd, errno: " << strerror(errno);
    }

    m_fds_ext_events = {amx_fd, amxp_fd};

    auto search_path = search_path_radio_by_iface(iface_name);
    m_ambiorix_cl->resolve_path(search_path, m_radio_path);

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

void base_wlan_hal_whm::subscribe_to_radio_events(const std::string &iface_name)
{
    // subscribe to the WiFi.Radio.iface_name.Status
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = {AMX_CL_OBJECT_CHANGED_EVT};
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        hal->process_radio_event(hal->get_iface_name(), event_data);
    };
    event_callback->context = this;
    std::string filter      = "path matches '" + m_radio_path + "'";
    filter.append(" && contains('parameters.Status')");
    m_ambiorix_cl->subscribe_to_object_event(m_radio_path, event_callback, filter);
}

void base_wlan_hal_whm::subscribe_to_ap_events(const std::string &iface_name)
{
    std::string wifi_ap_path            = search_path_ap();
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = {AMX_CL_OBJECT_CHANGED_EVT};
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        base_wlan_hal_whm *hal      = (static_cast<base_wlan_hal_whm *>(context));
        std::string ap_obj_path_str = GET_CHAR(event_data, "path");
        amxc_var_t *ap_obj;
        if (!hal->get_object(ap_obj, ap_obj_path_str)) {
            return;
        }
        std::string interface = get_ap_iface(ap_obj);
        if (interface.empty()) {
            amxc_var_delete(&ap_obj);
            return;
        }
        auto rad_ref = get_path_radio_reference(ap_obj);
        std::string rad_path;
        hal->get_amx_cli()->resolve_path(rad_ref, rad_path);
        amxc_var_delete(&ap_obj);
        if (rad_path.empty() || (hal->m_radio_path != rad_path)) {
            return;
        }
        hal->process_ap_event(interface, event_data);
    };
    event_callback->context = this;
    std::string filter      = "path matches '" + wifi_ap_path + "[0-9]+.'";
    filter.append(" && contains('parameters.Status')");
    m_ambiorix_cl->subscribe_to_object_event(wifi_ap_path, event_callback, filter);
}

void base_wlan_hal_whm::subscribe_to_ep_events(const std::string &iface_name)
{
    // subscribe to the WiFi.EndPoint.iface_name.ConnectionStatus
    std::string wifi_ep_path            = search_path_ap_by_iface(iface_name);
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = {AMX_CL_OBJECT_CHANGED_EVT};
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        hal->process_ep_event(hal->get_iface_name(), event_data);
    };
    event_callback->context = this;
    std::string filter      = "path matches '" + wifi_ep_path + "'";
    filter.append(" && contains('parameters.ConnectionStatus')");
    m_ambiorix_cl->subscribe_to_object_event(m_radio_path, event_callback, filter);
}

void base_wlan_hal_whm::subscribe_to_sta_events(const std::string &iface_name)
{
    std::string wifi_ad_path            = search_path_ap() + "[0-9]+.AssociatedDevice.";
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = {AMX_CL_OBJECT_CHANGED_EVT};
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        base_wlan_hal_whm *hal       = (static_cast<base_wlan_hal_whm *>(context));
        std::string sta_obj_path_str = GET_CHAR(event_data, "path");
        std::string ap_obj_path_str  = get_path_ap_iface_of_assocDev(sta_obj_path_str);
        amxc_var_t *ap_obj;
        if (!hal->get_object(ap_obj, ap_obj_path_str)) {
            return;
        }
        auto interface = get_ap_iface(ap_obj);
        amxc_var_delete(&ap_obj);
        auto vap_id = hal->get_vap_id_with_bss(interface);
        if (!hal->check_vap_id(vap_id)) {
            return;
        }
        std::string sta_mac("");
        hal->get_param<>(sta_mac, sta_obj_path_str, "MACAddress");
        if (sta_mac.empty()) {
            return;
        }
        hal->process_sta_event(interface, sta_mac, event_data);
    };
    event_callback->context = this;
    std::string filter      = "path matches '" + wifi_ad_path + "[0-9]+.'";
    filter.append(" && contains('parameters.AuthenticationState')");
    m_ambiorix_cl->subscribe_to_object_event(wifi_ad_path, event_callback, filter);
}

bool base_wlan_hal_whm::process_radio_event(const std::string &interface, const amxc_var_t *data)
{
    return true;
}

bool base_wlan_hal_whm::process_ap_event(const std::string &interface, const amxc_var_t *data)
{
    return true;
}

bool base_wlan_hal_whm::process_ep_event(const std::string &interface, const amxc_var_t *data)
{
    return true;
}

bool base_wlan_hal_whm::process_sta_event(const std::string &interface, const std::string &sta_mac,
                                          const amxc_var_t *data)
{
    return true;
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
    std::string sVal;
    get_param<>(m_radio_info.tx_power, m_radio_path, "TransmitPower");
    get_param<>(sVal, m_radio_path, "CurrentOperatingChannelBandwidth");
    beerocks::eWiFiBandwidth band = beerocks::wbapi::wbapi_utils::bandwith_from_string(sVal);
    m_radio_info.bandwidth        = beerocks::utils::convert_bandwidth_to_int(band);
    get_param<>(m_radio_info.wifi_ctrl_enabled, m_radio_path, "Enable");
    get_param<>(m_radio_info.channel, m_radio_path, "Channel");
    m_radio_info.is_5ghz =
        (son::wireless_utils::which_freq(m_radio_info.channel) == beerocks::eFreqType::FREQ_5G);
    get_param<>(sVal, m_radio_path, "Status");
    m_radio_info.radio_state = utils_wlan_hal_whm::radio_state_from_string(sVal);
    if (m_radio_info.radio_state == eRadioState::ENABLED) {
        m_radio_info.wifi_ctrl_enabled = 2; // Assume Operational
        m_radio_info.tx_enabled        = 1;
    }
    get_param<>(m_radio_info.ant_num, m_radio_path + "DriverStatus.", "NrTxAntenna");

    if (!m_radio_info.available_vaps.size()) {
        if (!refresh_vaps_info(beerocks::IFACE_RADIO_ID)) {
            return false;
        }
    }

    return true;
}

amxc_var_t *base_wlan_hal_whm::get_radio_vaps()
{
    amxc_var_t *plist  = nullptr;
    amxc_var_t *aps    = m_ambiorix_cl->get_object(search_path_ap(), 0, false);
    amxc_array_t *keys = amxc_htable_get_sorted_keys(amxc_var_constcast(amxc_htable_t, aps));
    uint32_t size      = amxc_array_size(keys);
    for (uint32_t i = 0; i < size; i++) {
        const char *abs_path = (const char *)amxc_array_get_data_at(keys, i);
        amxc_var_t *ap       = GET_ARG(aps, abs_path);
        std::string radio_path;
        if ((!ap) || (!get_amx_cli()->resolve_path(get_path_radio_reference(ap), radio_path)) ||
            (radio_path != m_radio_path)) {
            continue;
        }
        if (!plist) {
            if (amxc_var_new(&plist) != 0) {
                break;
            }
            amxc_var_set_type(plist, AMXC_VAR_ID_LIST);
        }
        LOG(DEBUG) << "Found vap " << amxc_var_key(ap) << " of rad " << m_radio_path;
        amxc_var_set_index(plist, -1, ap, AMXC_VAR_FLAG_COPY);
    }
    amxc_array_delete(&keys, NULL);
    amxc_var_delete(&aps);
    return plist;
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

    auto wifi_ssid_path = get_path_ssid_reference(ap_obj);
    auto ifname         = get_ap_iface(ap_obj);
    if (!wifi_ssid_path.empty() && !ifname.empty()) {
        amxc_var_t *ssid_obj = m_ambiorix_cl->get_object(wifi_ssid_path);
        if (!ssid_obj) {
            LOG(ERROR) << "failed to get ssid object " << wifi_ssid_path;
        } else if (std::string(GET_CHAR(ap_obj, "Status")) == "Enabled") {
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
            LOG(INFO) << "Removed VAP " << m_radio_info.available_vaps[id].bss << " id (" << id
                      << ") ";
            m_radio_info.available_vaps.erase(id);
        }

        return true;
    }

    // Store the VAP element
    LOG(INFO) << "Detected VAP id (" << id << ") - MAC: " << vap_element.mac
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
    if (m_ambiorix_cl->get_fd() == fd) {
        m_ambiorix_cl->read();
    } else if (m_ambiorix_cl->get_signal_fd() == fd) {
        m_ambiorix_cl->read_signal();
    }
    return true;
}

amxc_var_t *base_wlan_hal_whm::whm_get_wifi_ap_object(const std::string &iface)
{
    std::string ap_path = search_path_ap_by_iface(iface);
    return m_ambiorix_cl->get_object(ap_path);
}

amxc_var_t *base_wlan_hal_whm::whm_get_wifi_ssid_object(const std::string &iface)
{
    // pwhm dm path: WiFi.SSID.[ Alias == 'iface' ].?
    std::string ssid_path = search_path_ssid_by_iface(iface);
    return m_ambiorix_cl->get_object(ssid_path);
}

int base_wlan_hal_whm::whm_get_vap_id(const std::string &iface)
{
    bool found      = false;
    int vap_id      = beerocks::IFACE_VAP_ID_MIN;
    amxc_var_t *aps = get_radio_vaps();
    amxc_var_for_each(ap, aps)
    {
        if (get_ap_iface(ap) == iface) {
            found = true;
            break;
        }
        vap_id++;
    }
    amxc_var_delete(&aps);
    if (found) {
        return vap_id;
    }
    return int(beerocks::IFACE_ID_INVALID);
}

bool base_wlan_hal_whm::whm_get_radio_ref(const std::string &iface, std::string &ref)
{
    ref                = "";
    amxc_var_t *ap_obj = whm_get_wifi_ap_object(iface);
    if (!ap_obj) {
        LOG(ERROR) << "failed to get ap object of iface " << iface;
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
    return m_ambiorix_cl->resolve_path(search_path_radio_by_iface(iface), path);
}

std::string base_wlan_hal_whm::get_radio_mac()
{
    std::string mac("");
    std::string wifi_radio_path = search_path_radio_by_iface(get_iface_name());
    get_param<>(mac, wifi_radio_path, "BaseMACAddress");
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
