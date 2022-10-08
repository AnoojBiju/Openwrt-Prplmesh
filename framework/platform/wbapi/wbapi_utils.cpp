/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "wbapi_utils.h"

namespace beerocks {
namespace wbapi {

beerocks::eWiFiBandwidth wbapi_utils::bandwith_from_string(const std::string &band)
{
    if (band == "160MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_160;
    } else if (band == "80MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_80;
    } else if (band == "40MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_40;
    } else if (band == "20MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_20;
    } else {
        return beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN;
    }
}

beerocks::eFreqType wbapi_utils::band_to_freq(const std::string &band)
{
    if (band == "2.4GHz") {
        return beerocks::eFreqType::FREQ_24G;
    } else if (band == "5GHz") {
        return beerocks::eFreqType::FREQ_5G;
    } else if (band == "6GHz") {
        return beerocks::eFreqType::FREQ_6G;
    } else {
        LOG(ERROR) << "not Supported FreqBand value: " << band;
        return beerocks::eFreqType::FREQ_UNKNOWN;
    }
}

std::string wbapi_utils::security_mode_to_string(const WSC::eWscAuth &security_mode)
{
    std::string sec_mode = "None";
    if (security_mode == WSC::eWscAuth::WSC_AUTH_WPA2PSK ||
        security_mode == WSC::eWscAuth::WSC_AUTH_WPA2) {
        sec_mode = "WPA2-Personal";
    } else if (security_mode == WSC::eWscAuth::WSC_AUTH_WPAPSK ||
               security_mode == WSC::eWscAuth::WSC_AUTH_WPA) {
        sec_mode = "WPA-Personal";
    }
    return sec_mode;
}

WSC::eWscAuth wbapi_utils::security_mode_from_string(const std::string &security_mode)
{
    WSC::eWscAuth sec_mode = WSC::eWscAuth::WSC_AUTH_OPEN;
    if (security_mode == "WPA-Personal") {
        sec_mode = WSC::eWscAuth::WSC_AUTH_WPA;
    } else if (security_mode == "WPA2-Personal") {
        sec_mode = WSC::eWscAuth::WSC_AUTH_WPA2;
    }
    return sec_mode;
}

std::string wbapi_utils::encryption_type_to_string(const WSC::eWscEncr &encryption_type)
{
    std::string encrypt_mode = "Default";
    if (encryption_type == WSC::eWscEncr::WSC_ENCR_AES) {
        encrypt_mode = "AES";
    } else if (encryption_type == WSC::eWscEncr::WSC_ENCR_TKIP) {
        encrypt_mode = "TKIP";
    }
    return encrypt_mode;
}

WSC::eWscEncr wbapi_utils::encryption_type_from_string(const std::string &encryption_type)
{
    WSC::eWscEncr encrypt_mode = WSC::eWscEncr::WSC_ENCR_NONE;
    if (encryption_type == "AES") {
        encrypt_mode = WSC::eWscEncr::WSC_ENCR_AES;
    } else if (encryption_type == "TKIP") {
        encrypt_mode = WSC::eWscEncr::WSC_ENCR_TKIP;
    }
    return encrypt_mode;
}

int wbapi_utils::get_object_id(const std::string &object_path)
{
    auto str = object_path;
    if (str.back() == '.') {
        str.pop_back();
    }
    auto pos = str.rfind('.');
    if (pos == std::string::npos) {
        return 0;
    }
    auto token = str.substr(pos + 1);
    if (token.find_first_not_of("0123456789") != std::string::npos) {
        return 0;
    }
    return stoi(token);
}

std::string wbapi_utils::get_string(const char *buf, const char *pad)
{
    if (!buf || !buf[0]) {
        return "";
    }
    auto ret = std::string(buf);
    if (pad && pad[0]) {
        return ret + pad;
    }
    return ret;
}

std::string wbapi_utils::search_path_wifi() { return std::string("WiFi."); }

std::string wbapi_utils::search_path_radio() { return search_path_wifi() + "Radio."; }

std::string wbapi_utils::search_path_ssid() { return search_path_wifi() + "SSID."; }

std::string wbapi_utils::search_path_ap() { return search_path_wifi() + "AccessPoint."; }

std::string wbapi_utils::search_path_ep() { return search_path_wifi() + "EndPoint."; }

std::string wbapi_utils::search_path_radio_iface() { return search_path_radio() + "*.Name"; }

std::string wbapi_utils::search_path_radio_by_iface(const std::string &rad_ifname)
{
    return search_path_radio() + "[Name == '" + rad_ifname + "'].";
}

std::string wbapi_utils::search_path_ssid_by_iface(const std::string &ssid_ifname)
{
    return search_path_ssid() + "[Name == '" + ssid_ifname + "'].";
}

std::string wbapi_utils::search_path_ap_by_iface(const std::string &vap_ifname)
{
    return search_path_ap() + "[Alias == '" + vap_ifname + "'].";
}

std::string wbapi_utils::search_path_ap_by_radRef(const std::string &radioRef)
{
    return search_path_ap() + "[RadioReference == '" + radioRef + "'].";
}

std::string wbapi_utils::search_path_ap_iface_by_radRef(const std::string &radioRef)
{
    return search_path_ap_by_radRef(radioRef) + "Alias";
}

std::string wbapi_utils::search_path_assocDev_by_mac(const std::string &vap_ifname,
                                                     const std::string &mac)
{
    return search_path_ap_by_iface(vap_ifname) + "AssociatedDevice." + "[MACAddress == '" + mac +
           "'].";
}

std::string wbapi_utils::search_path_ep_by_iface(const std::string &ep_ifname)
{
    return search_path_ep() + "[IntfName == '" + ep_ifname + "'].";
}

std::string wbapi_utils::search_path_ep_profiles_by_iface(const std::string &ep_ifname)
{
    return search_path_ep_by_iface(ep_ifname) + "Profile.";
}

std::string wbapi_utils::search_path_ep_profile_by_id(const std::string &ep_ifname,
                                                      uint32_t profile_id)
{
    return search_path_ep_profiles_by_iface(ep_ifname) + std::to_string(profile_id) + ".";
}

std::string wbapi_utils::get_path_radio_reference(const amxc_var_t *obj)
{
    return get_string(GET_CHAR(obj, "RadioReference"), ".");
}

std::string wbapi_utils::get_path_ssid_reference(const amxc_var_t *obj)
{
    return get_string(GET_CHAR(obj, "SSIDReference"), ".");
}

std::string wbapi_utils::get_path_radio_iface(const std::string &radio_path)
{
    return get_string(radio_path.c_str(), "Name");
}

std::string wbapi_utils::get_path_ap_iface(const std::string &ap_path)
{
    return get_string(ap_path.c_str(), "Alias");
}

std::string wbapi_utils::get_path_ap_iface_of_assocDev(const std::string &assocDev_path)
{
    auto pos = assocDev_path.rfind("AssociatedDevice");
    if (pos == std::string::npos) {
        return "";
    }
    return get_path_ap_iface(assocDev_path.substr(0, pos));
}

std::string wbapi_utils::wbapi_utils::get_ap_iface(const amxc_var_t *obj)
{
    return get_string(GET_CHAR(obj, "Alias"));
}

std::string wbapi_utils::get_ssid_iface(const amxc_var_t *obj)
{
    return get_string(GET_CHAR(obj, "Alias"));
}

std::string wbapi_utils::get_ep_iface(const amxc_var_t *obj)
{
    return get_string(GET_CHAR(obj, "IntfName"));
}

bool wbapi_utils::get_object(amxc_var_t *&result, const std::string &obj_path)
{
    result = get_amx_cli()->get_object(obj_path);
    return (result != nullptr);
}

template <>
bool wbapi_utils::get_param<>(amxc_var_t *&result, const std::string &obj_path,
                              const std::string &param_name)
{
    amxc_var_t *entry      = nullptr;
    std::string param_path = obj_path + param_name;
    if (get_object(entry, param_path)) {
        result = amxc_var_get_first(entry);
        amxc_var_take_it(result);
        amxc_var_delete(&entry);
        return true;
    }
    return false;
}

template <>
bool wbapi_utils::get_param<>(std::string &result, const std::string &obj_path,
                              const std::string &param_name)
{
    amxc_var_t *pRes = nullptr;
    if (get_param<>(pRes, obj_path, param_name)) {
        result = amxc_var_constcast(cstring_t, pRes);
        amxc_var_delete(&pRes);
        return true;
    }
    return false;
}

template <>
bool wbapi_utils::get_param<>(bool &result, const std::string &obj_path,
                              const std::string &param_name)
{
    amxc_var_t *pRes = nullptr;
    if (get_param<>(pRes, obj_path, param_name)) {
        result = amxc_var_dyncast(bool, pRes);
        amxc_var_delete(&pRes);
        return true;
    }
    return false;
}

template <>
bool wbapi_utils::get_param<>(int &result, const std::string &obj_path,
                              const std::string &param_name)
{
    amxc_var_t *pRes = nullptr;
    if (get_param<>(pRes, obj_path, param_name)) {
        result = amxc_var_dyncast(int32_t, pRes);
        amxc_var_delete(&pRes);
        return true;
    }
    return false;
}

template <typename T>
bool wbapi_utils::get_param(T &result, const std::string &obj_path, const std::string &param_name)
{
    return false;
}

} // namespace wbapi
} // namespace beerocks
