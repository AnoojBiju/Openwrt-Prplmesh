/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _WBAPI_UTILS_H_
#define _WBAPI_UTILS_H_

#include "ambiorix_variant.h"
#include <bcl/beerocks_defines.h>
#include <easylogging++.h>
#include <tlvf/WSC/eWscAuth.h>
#include <tlvf/WSC/eWscEncr.h>

namespace beerocks {
namespace wbapi {

class wbapi_utils {

public:
    /**
     * @brief Converts a string-based bandwith to beerocks::eWiFiBandwidth.
     */
    static beerocks::eWiFiBandwidth bandwith_from_string(const std::string &bandwidth);

    /**
     * @brief Converts a string-based bandwidth
     * (Ref TR181 Device.WiFi.Radio.{i}.SupportedFrequencyBands: 2.4GHz, 5GHz, 6GHz
     * to beerocks::eFreqType.
     */
    static beerocks::eFreqType band_to_freq(const std::string &band);

    /**
     * @brief Converts a string-based bandwidth
     * (Ref TR181 Device.WiFi.Radio.{i}.SupportedFrequencyBands: 2.4GHz, 5GHz, 6GHz
     * to band description string (24g, 5g, 6g).
     */
    static std::string band_short_name(const std::string &band);

    /**
     * @brief Converts WSC::eWscAuth ecurity mode to string.
     */
    static std::string security_mode_to_string(const WSC::eWscAuth &security_mode);

    /**
     * @brief Converts a string-based security mode to WSC::eWscAuth.
     */
    static WSC::eWscAuth security_mode_from_string(const std::string &security_mode);

    /**
     * @brief Converts a beerocks::eFreqType encryption type to string.
     */
    static std::string encryption_type_to_string(const WSC::eWscEncr &encryption_type);

    /**
     * @brief Converts a string-based encryption type to WSC::eWscEncr.
     */
    static WSC::eWscEncr encryption_type_from_string(const std::string &encryption_type);

    /**
     * @brief get amxc var object id from the object path.
     * eg: "RootObj.TemplateObj.id" or "RootObj.TemplateObj.id."
     *
     * @return instance id , greater than 0 if successful, 0 otherwise
     */
    static int get_object_id(const std::string &object_path);

    /**
     * @brief return path of WiFi root object.
     */
    static std::string search_path_wifi();

    /**
     * @brief return path of Radio template object.
     */
    static std::string search_path_radio();

    /**
     * @brief return path of SSID template object.
     */
    static std::string search_path_ssid();

    /**
     * @brief return path of AccessPoint template object.
     */
    static std::string search_path_ap();

    /**
     * @brief return path of EndPoint template object.
     */
    static std::string search_path_ep();

    /**
     * @brief return search path of Radio object instance's Name.
     */
    static std::string search_path_radio_iface();

    /**
     * @brief return search path of Radio object instance by Name.
     */
    static std::string search_path_radio_by_iface(const std::string &rad_ifname);

    /**
     * @brief return search path of SSID object instance's Name.
     */
    static std::string search_path_ssid_iface();

    /**
     * @brief return search path of SSID object instance by interface name.
     */
    static std::string search_path_ssid_by_iface(const std::string &ssid_ifname);

    /**
     * @brief return search path of SSID object instance by BSSID mac address.
     */
    static std::string search_path_ssid_by_bssid(const std::string &bssid);

    /**
     * @brief return search path of SSID object instance Name by BSSID mac address.
     */
    static std::string search_path_ssid_iface_by_bssid(const std::string &bssid);

    /**
     * @brief return search path of AccessPoint object interface Name.
     */
    static std::string search_path_ap_iface();

    /**
     * @brief return search path of AccessPoint object instance by interface name.
     */
    static std::string search_path_ap_by_iface(const std::string &vap_ifname);

    /**
     * @brief return search path of AccessPoint object instances by radio reference.
     */
    static std::string search_path_ap_by_radRef(const std::string &radioRef);

    /**
     * @brief return search path of all AccessPoint object instance's interfaces
     * filtered by radio reference.
     */
    static std::string search_path_ap_iface_by_radRef(const std::string &radioRef);

    /**
     * @brief return search path of associated device object instance
     * filter by MAC address.
     */
    static std::string search_path_assocDev_by_mac(const std::string &vap_ifname,
                                                   const std::string &mac);

    /**
     * @brief return search path of EndPoint object instance by interface name.
     */
    static std::string search_path_ep_by_iface(const std::string &ep_ifname);

    /**
     * @brief return search path of EndPoint profile object instance by endpoint interface name.
     */
    static std::string search_path_ep_profiles_by_iface(const std::string &ep_ifname);

    /**
     * @brief return search path of EndPoint EndPoint profile object instance by index
     */
    static std::string search_path_ep_profile_by_id(const std::string &ep_ifname,
                                                    uint32_t profile_id);

    /**
     * @brief return accesspoint object instance path from path of child AssociatedDevice object
     * instance
     */
    static std::string get_path_ap_of_assocDev(const std::string &assocDev_path);

    /**
     * @brief return interface name param path of radio object instance
     */
    static std::string get_path_radio_iface(const std::string &radio_path);

    /**
     * @brief return interface name param path of AccessPoint object instance
     */
    static std::string get_path_ap_iface(const std::string &ap_path);

    /**
     * @brief return radio instance path from radio reference param of an upper layer object
     */
    static std::string get_path_radio_reference(const AmbiorixVariant &obj);

    /**
     * @brief return ssid instance path from ssid reference param of an upper layer object
     */
    static std::string get_path_ssid_reference(const AmbiorixVariant &obj);

    /**
     * @brief get interface name of AccessPoint object data
     */
    static std::string get_ap_iface(const AmbiorixVariant &obj);

    /**
     * @brief get status of AccessPoint object data
     */
    static std::string get_ap_status(const AmbiorixVariant &obj);

    /**
     * @brief get mac address of SSID object data
     */
    static std::string get_ssid_mac(const AmbiorixVariant &obj);

    /**
     * @brief get interface name of Radio object data
     */
    static std::string get_radio_iface(const AmbiorixVariant &obj);

    /**
     * @brief get interface name of SSID object data
     */
    static std::string get_ssid_iface(const AmbiorixVariant &obj);

    /**
     * @brief get interface name of EndPoint object data
     */
    static std::string get_ep_iface(const AmbiorixVariant &obj);

    /**
     * @brief return search path of AccessPoint's MAC filters object
     */
    static std::string search_path_mac_filtering(const std::string &vap_ifname);

    /**
     * @brief return search path of AccessPoint's MAC filter entry object
     * by station mac
     */
    static std::string search_path_mac_filtering_entry_by_mac(const std::string &vap_ifname,
                                                              const std::string &mac);

private:
    /**
     * @brief Convertion table of channel bandwidth from string to beerocks::eWiFiBandwidth.
     */
    static const std::map<std::string, beerocks::eWiFiBandwidth> band_width_table;

    /**
     * @brief Convertion table of Frequency band from string value
     * to short description string and beerocks::eFreqType.
     */
    static const std::map<std::string, std::pair<std::string, beerocks::eFreqType>> band_freq_table;

    /**
     * @brief Convertion table of Security mode from string to WSC::eWscAuth.
     */
    static const std::map<std::string, std::vector<WSC::eWscAuth>> security_mode_table;

    /**
     * @brief Convertion table of encryption type from string to WSC::eWscEncr.
     */
    static const std::map<std::string, std::vector<WSC::eWscEncr>> encryption_type_table;
};

} // namespace wbapi
} // namespace beerocks

#endif // _WBAPI_UTILS_H_
