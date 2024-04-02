/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PRPLMESH_CLI_H
#define _PRPLMESH_CLI_H

#ifndef AMBIORIX_BACKEND_PATH
#define AMBIORIX_BACKEND_PATH "/usr/bin/mods/amxb/mod-amxb-ubus.so"
#endif // AMBIORIX_BACKEND_PATH

#ifndef AMBIORIX_BUS_URI
#define AMBIORIX_BUS_URI "ubus:"
#endif // AMBIORIX_BUS_URI

#ifndef BRIDGE_IFACE
#define BRIDGE_IFACE "br-lan"
#endif //BRIDGE_IFACE

#include <map>
#include <string>
#include <vector>

#include "prplmesh_amx_client.h"

namespace beerocks {
namespace prplmesh_api {

enum operating_mode {
    PPM_OPMODE_NONE                 = 0b00,
    PPM_OPMODE_AGENT_ONLY           = 0b01,
    PPM_OPMODE_CONTROLLER_ONLY      = 0b10,
    PPM_OPMODE_AGENT_AND_CONTROLLER = PPM_OPMODE_AGENT_ONLY | PPM_OPMODE_CONTROLLER_ONLY,
};

inline std::string to_string(operating_mode mode)
{
    switch (mode) {
    default:
    case PPM_OPMODE_NONE:
        return "Not operational";
    case PPM_OPMODE_AGENT_ONLY:
        return "Agent only";
    case PPM_OPMODE_CONTROLLER_ONLY:
        return "Controller only";
    case PPM_OPMODE_AGENT_AND_CONTROLLER:
        return "Agent+Controller";
    }
}

class prplmesh_cli {
public:
    prplmesh_cli();
    bool get_ip_from_iface(const std::string &iface, std::string &ip);
    bool prpl_conn_map();
    void print_help();
    void print_version();
    operating_mode get_operating_mode(bool &agt_timed_out, bool &ctl_timed_out);

    /**
     * @brief Get an AP path by index or SSID
     * 
     * @param[in] ap #<index> or string (use ## if SSID starts with #)
     */
    std::string get_ap_path(std::string ap);

    /**
     * @brief Show existing Access Point details
     */
    void show_ap();
    /**
     * @brief Change the SSID of an access point
     *
     * @param[in] ap The Access Point to the SSID on
     * @param[in] ssid The SSID to set
     */
    bool set_ssid(const std::string &ap, const std::string &ssid);
    /**
     * @brief Set the security of an access point
     *
     * @param[in] ap The Access Point to modify
     * @param[in] mode The security type (e.g. WPA2) to use. Must be a valid and supported algorithm
     * @param[in] passphrase The pass phrase to use
     */
    bool set_security(const std::string &ap, const std::string &mode,
                      const std::string &passphrase);

    /**
    * @brief Recursive function that prints the topology of agents.
    * 
    * Each agent has a master agent or controller.
    * The purpose of the recursion is to check if the current agent is the master of another
    * (compare mac of the current agent and the BackhaulDeviceID of other agents).
    * If it is equal, display the dependent agent on the console. Use dependent agent as a master now.
    * If it isn't equal then switch to another agent.
    * 
    * @param[in] agent_mac String containing the mac address of master device
    * @param[in] skip_mac String containing the mac address of the device that should not be printed
    * @return True on success, false otherwise.
    */
    bool print_device_info(std::string agent_mac, std::string skip_mac);

    /**
    * @brief Print information per one Radio.
    * 
    * @param[in] device_path String containing the path to the Device.
    * @return True on success, false otherwise.
    */
    bool print_radio(std::string device_path);

    /**
    * @brief Print current prplMesh mode.
    *
    * Possible output: "Not operational", "Agent only", "Controller only", "Agent+Controller"
    */
    bool print_mode();

    /**
    * @brief Print prplMesh status information.
    *
    * This is meant to replace the old status check in prplmesh_utils.sh that greps log files for the operational status.
    * It will inspect the data model to determine the status and configuration of prplMesh.
    *
    * @return True on successful retrieval of status (even if the status is bad), false if unable to get the status.
    */
    bool print_status(const std::string &format);

    /**
    * @brief Get frequency using operating classes.
    * 
    * IEEE Std 802.11™‐2020 - Global operating classes
    * 
    * @param[in] oper_class uint32_t operating class value.
    * @return freq on success, 0 otherwise.
    */
    float get_freq_from_class(const uint32_t oper_class);

    std::shared_ptr<beerocks::prplmesh_amx::AmxClient> m_amx_client;

    typedef struct conn_map_t {
        std::string device_ht_path = CONTROLLER_ROOT_DM ".Network.Device.*.";
        uint32_t device_number;
        std::string controller_id;
        std::string bridge_ip_v4;
        std::string radio_id;
        std::string bss_id;
        std::string ssid;
        uint32_t channel;
        uint32_t oper_class;
        uint32_t device_index = 1;
    } conn_map_t;

private:
};

} // namespace prplmesh_api
} // namespace beerocks

#endif // _PRPLMESH_CLI_H
