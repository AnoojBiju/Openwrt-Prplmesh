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

} // namespace bpl
} // namespace beerocks
