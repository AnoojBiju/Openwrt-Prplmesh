/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _WBAPI_UTILS_H_
#define _WBAPI_UTILS_H_

#include "ambiorix_client.h"
#include <bcl/beerocks_defines.h>
#include <easylogging++.h>
#include <tlvf/WSC/eWscAuth.h>
#include <tlvf/WSC/eWscEncr.h>

namespace beerocks {
namespace wbapi {

class wbapi_utils {

protected:
    /**
     * @brief virtual abstract method to get access to ambiorix client context.
     * optional suffix.
     *
     * @return shared pointer of ambiorix client.
     */
    virtual const std::unique_ptr<beerocks::wbapi::AmbiorixClient> &get_amx_cli() = 0;

    /**
     * @brief request full object content of a provided path.
     *
     * @param[out] result: pointer to amxc_var_t, filled with object content.
     *                     (To be cleared after usage)
     * @param[in] obj_path: object datamodel path.
     * @return true on success, false otherwise.
     */
    bool get_object(amxc_var_t *&result, const std::string &obj_path);

    /**
     * @brief request parameter value of a provided parameter path
     * and converts it to basic types through template specialization.
     *
     * @param[out] result: reference to typed result, filled after conversion
     *                     with the parameter value
     * @param[in] obj_path: parent object path.
     * @param[in] param_name: parameter name.
     * @return true on success, false otherwise.
     */
    template <typename T>
    bool get_param(T &result, const std::string &obj_path, const std::string &param_name);

public:
    wbapi_utils()          = default;
    virtual ~wbapi_utils() = default;

    /**
     * @brief Converts a string-based bandwith to beerocks::eWiFiBandwidth.
     */
    static beerocks::eWiFiBandwidth bandwith_from_string(const std::string &band);

    /**
     * @brief Converts a string-based bandwith to beerocks::eFreqType.
     */
    static beerocks::eFreqType band_to_freq(const std::string &band);

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
     * @brief return search path of SSID object instance by interface name.
     */
    static std::string search_path_ssid_by_iface(const std::string &ssid_ifname);

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
     * @brief return radio instance path from radio reference param of an upper layer object
     */
    static std::string get_path_radio_reference(const amxc_var_t *obj);

    /**
     * @brief return ssid instance path from ssid reference param of an upper layer object
     */
    static std::string get_path_ssid_reference(const amxc_var_t *obj);

    /**
     * @brief return interface name param path of radio object instance
     */
    static std::string get_path_radio_iface(const std::string &radio_path);

    /**
     * @brief return interface name param path of AccessPoint object instance
     */
    static std::string get_path_ap_iface(const std::string &ap_path);

    /**
     * @brief return accesspoint object instance path from path of child AssociatedDevice object
     * instance
     */
    static std::string get_path_ap_iface_of_assocDev(const std::string &assocDev_path);

    /**
     * @brief get interface name of AccessPoint object data
     */
    static std::string get_ap_iface(const amxc_var_t *obj);

    /**
     * @brief get interface name of SSID object data
     */
    static std::string get_ssid_iface(const amxc_var_t *obj);

    /**
     * @brief get interface name of EndPoint object data
     */
    static std::string get_ep_iface(const amxc_var_t *obj);

private:
    /**
     * @brief build string path from static char buf and optional suffix.
     *
     * @param[in] buf: base string content.
     * @param[in] pad: optional suffix.
     * @return string with concatenated values.
     */
    static std::string get_string(const char *buf, const char *pad = "");
};

} // namespace wbapi
} // namespace beerocks

#endif // _WBAPI_UTILS_H_
