/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2023 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "bpl_network.h"

#include <easylogging++.h>

#include <ambiorix_connection_manager.h>

using namespace beerocks;
using namespace wbapi;

namespace beerocks {
namespace bpl {

/**
 * @brief get port name
 *
 * @param[in] port_path: absolute path to the port
 * @param[out] port_name: name of the port (if empty in port datamodel, will try to retrieve from lower layer)
 * @return true if a non-zero length string was read from the datamodel and written to the port_name,
 * false otherwise
*/
static bool get_bridge_port_name(const std::string &port_path, std::string &port_name)
{

    LOG(INFO) << "get port name for " << port_path;

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
    }

    std::string tmp_name = amxb_connection->get_param(port_path, "Name")->get<std::string>();

    if (!tmp_name.length()) {
        //try to get name from lower layer
        LOG(ERROR) << "name for " << port_path
                   << " not configured, retrieving name from LowerLayers";
        std::string port_ll =
            amxb_connection->get_param(port_path, "LowerLayers")->get<std::string>();
        std::string ll_name = amxb_connection->get_param(port_ll, "Name")->get<std::string>();
        if (!ll_name.length()) {
            LOG(ERROR) << "can't retrieve port name from LowerLayers for " << port_path;
            return false;
        }
        tmp_name = ll_name;
    }

    port_name = tmp_name;
    LOG(DEBUG) << port_path << " name " << port_name;
    return true;
}

/**
 * @brief get a lower layer object corresponding to the interface name; as of now, only
 *        search in WiFi.SSID.[i] and Ethernet.Interface[i] instances
 * @param[in] iface : interface name that is to be searched among possible lower layers
 * @param[out] dm_path : path starting with "Device." if found
 * @return bool : true if dm_path was written into
*/

static bool get_lower_layer_for_interface(const std::string &iface, std::string &dm_path)
{
    LOG(DEBUG) << "get iface lower layer object path for " << iface;

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
    }

    std::string ssid_filter = "Device.WiFi.SSID.[Name == '" + iface + "'].";
    std::string eth_filter  = "Device.Ethernet.Interface.[Name == '" + iface + "'].";

    std::vector<std::string> port_paths;

    if (!amxb_connection->resolve_path(ssid_filter, port_paths)) {
        if (!amxb_connection->resolve_path(eth_filter, port_paths)) {
            LOG(ERROR) << "cannot retrieve the interface object corresponding to " << iface;
            return false;
        }
    }
    // if we got here, at least one (and at most one) resolve path was successful
    dm_path = port_paths[0];
    return true;
}

/**
 * @brief get the path of a bridge port for the given interface
 * 
 * @param[in] bridge : name of the bridge interface
 * @param[in] iface  : name of the interface
 * @param[out] port  : full path of the port instance
*/
static bool get_bridge_port_path(const std::string &bridge, const std::string &iface,
                                 std::string &port)
{
    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
    }
    std::string bridge_filter    = "Bridge.[Alias == '" + bridge + "'].";
    std::string port_filter      = "Port.[ManagementPort == 0].";
    std::string port_search_path = "Device.Bridging." + bridge_filter + port_filter;

    LOG(DEBUG) << "retrieve bridge ports with search path " << port_search_path;

    std::vector<std::string> port_paths;
    if (!amxb_connection->resolve_path(port_search_path, port_paths)) {
        LOG(ERROR) << "cannot retrieve the port objects corresponding to " << port_search_path;
        return false;
    }

    std::string tmp_str;
    for (auto const &port_path : port_paths) {
        if (!get_bridge_port_name(port_path, tmp_str)) {
            continue;
        }
        if (tmp_str == iface) {
            port = port_path;
            return true;
        }
    }
    return false;
}

/**
 * @brief get a vector of port paths from the management port of bridge
 * @param[in] bridge : the target bridge alias
 * @param[out] port_paths : vector<string> of port paths
*/
static bool get_management_port_lower_layers(const std::string &bridge,
                                             std::vector<std::string> &port_paths)
{
    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    std::string bridge_filter    = "Bridge.[Alias == '" + bridge + "'].";
    std::string port_filter      = "Port.[ManagementPort == 1].";
    std::string port_search_path = "Device.Bridging." + bridge_filter + port_filter;

    std::string mp_path; // management port
    std::vector<std::string> mp_path_vec;
    if (amxb_connection->resolve_path(port_search_path, mp_path_vec)) {
        mp_path = mp_path_vec[0];
    } else {
        LOG(ERROR) << "can't retrieve management port for " << bridge;
        return false;
    }

    std::string mp_lower_layers =
        amxb_connection->get_param(mp_path, "LowerLayers")->get<std::string>();

    LOG(INFO) << "lower layers for management port " << mp_lower_layers;
    std::stringstream lower_layers_ss(mp_lower_layers);

    for (std::string port; std::getline(lower_layers_ss, port, ',');) {
        port_paths.push_back(port);
    }
    return true;
}

static bool set_port_enable_state(const std::string &port_object, const bool &state)
{
    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child<bool>("Enable", state);
    if (!amxb_connection->update_object(port_object, args)) {
        LOG(ERROR) << "can't set the Enable flag for " << port_object;
        return false;
    }
    return true;
}

static bool enable_port(const std::string &port_object)
{
    return set_port_enable_state(port_object, true);
}

/*static bool disable_port(const std::string &port_object)
{
    return set_port_enable_state(port_object, false);
}
commented out since it triggers an "unused function" error
*/

std::vector<std::string> bpl_network::get_iface_list_from_bridge(const std::string &bridge_name)
{
    std::vector<std::string> ifs;
    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
    }

    std::string bridge = bridge_name.substr(bridge_name.find("-") + 1);
    // extract bridge alias from bridge name: substring starting after the dash

    std::vector<std::string> port_paths;
    if (!get_management_port_lower_layers(bridge, port_paths)) {
        LOG(ERROR) << "can't retrieve lower layer for the management port of " << bridge;
        return ifs;
    }

    for (auto port : port_paths) {
        std::string port_name;
        if (!get_bridge_port_name(port, port_name)) {
            continue;
        }
        ifs.push_back(port_name);
    }
    return ifs;
}

/**
 * @brief Add an interface to the bridge; the interface can be of type eth or wireless
 * i.e. currently support only Ethernet.Interface.[i] and WiFi.SSID.[i] as lower layer for Bridge.Port
 * @param[in] bridge : name of the bridge
 * @param[in] iface : name of the interface; the wireless interfaces can have a multitude of names
 * the function does not expect a naming convention for the wireless interfaces, it would just look for
 * the name of the interface in both possible lower layers objects that are currently supported
 * Device.Ethernet.Interface.*.Name or Device.WiFi.SSID.*.Name
 * The corresponding lower layer object will be used;
 * @return bool : true if added successfully or already in bridge, false otherwise
*/
bool bpl_network::add_iface_to_bridge(const std::string &bridge_name, const std::string &iface)
{
    std::string bridge = bridge_name.substr(bridge_name.find("-") + 1);
    // extract bridge alias from bridge name: substring starting after the dash
    // the agent operates with the names of the bridge interfaces: br-lan, br-guest, br-lcm;
    // these names appear to be constructed by tr-181 bridging by prefixin with br-

    std::vector<std::string> port_paths;
    if (!get_management_port_lower_layers(bridge, port_paths)) {
        LOG(ERROR) << "can't retrieve lower layers list for the management port of " << bridge;
        return false;
    }

    std::string interface_port_path;
    if (get_bridge_port_path(bridge, iface, interface_port_path)) {
        LOG(INFO) << "bridge port for interface " << iface << " is " << interface_port_path;
        enable_port(interface_port_path); // port already exists, enable it
        if (std::find(port_paths.begin(), port_paths.end(), interface_port_path) !=
            port_paths.end()) {
            LOG(INFO) << "interface " << iface << " already in bridge";
            return true;
        } else {
            LOG(ERROR) << "interface " << iface << " port " << interface_port_path
                       << " configured but not in lower layers of management port";
            // a tr181-bridging bug that should not be handled by the agent
        }
    }

    std::string interface_object_path;
    // the interface that will be used as lowerlayer for the bridge.port

    if (!get_lower_layer_for_interface(iface, interface_object_path)) {
        LOG(ERROR) << "can't retrieve the interface object for " << iface;
        return false;
    }

    LOG(INFO) << "lower layer for interface " << iface << " is " << interface_object_path;

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    // create a new instance of Bridge.Port for the iface
    std::string bridge_filter = "Device.Bridging.Bridge.[Alias =='" + bridge + "'].";
    std::vector<std::string> bridge_path_vec;
    if (!amxb_connection->resolve_path(bridge_filter, bridge_path_vec)) {
        LOG(ERROR) << "can't retrieve bridge with search path " << bridge_filter;
        return false;
    }
    std::string bridge_port_template = bridge_path_vec[0] + "Port.";

    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);

    args.add_child<>("Name", iface);
    args.add_child<>("LowerLayers", interface_object_path);
    args.add_child<bool>("Enable", true);
    // gl-inet known issue : setting the Enable flag to true erases the port name

    int new_instance_id;
    // don't really need this value, but need a writable int for amxb_connexion->add_instance

    if (amxb_connection->add_instance(bridge_port_template, args, new_instance_id)) {
        LOG(DEBUG) << "added new instance " << new_instance_id;
        return true;
    }

    LOG(ERROR) << "failed to add new instance";
    return false;
}

} // namespace bpl
} // namespace beerocks
