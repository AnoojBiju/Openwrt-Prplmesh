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

std::vector<std::string> bpl_network::get_iface_list_from_bridge(const std::string &bridge_name)
{
    std::vector<std::string> ifs;
    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
    }

    std::string bridge_alias = bridge_name.substr(bridge_name.find("-") + 1);
    // extract bridge alias from bridge name: substring starting after the dash

    std::string bridge_filter    = "Bridge.[Alias == '" + bridge_alias + "' && Enable == 1].";
    std::string port_filter      = "Port.[ManagementPort == 0].";
    std::string port_search_path = "Bridging." + bridge_filter + port_filter;

    LOG(INFO) << "iacob bridge search path " << port_search_path;

    //inlining the ambiorix_client::get_objects_multi() function
    auto bridge_ports_obj = amxb_connection->get_object(port_search_path, 0, false);
    if (!bridge_ports_obj) {
        LOG(ERROR) << "can't retrieve bridge ports for " << bridge_alias;
        return ifs;
    }
    auto bridge_ports_map = bridge_ports_obj->take_childs<AmbiorixVariantMapSmartPtr>();

    if (!bridge_ports_map) {
        LOG(ERROR) << "can't flatten port objects into a map";
        return ifs;
    }
    for (auto const &it : *bridge_ports_map) {
        auto port = it.second;
        int port_enable; // port config
        std::string port_lower_layers;
        std::string port_name;

        port.read_child<>(port_enable, "Enable");
        port.read_child<>(port_lower_layers, "LowerLayers");
        port.read_child<>(port_name, "Name");

        std::stringstream port_desc;
        port_desc << "port " << it.first << " name " << port_name << " name length "
                  << port_name.length() << " lower layers " << port_lower_layers << " enable "
                  << port_enable;
        std::stringstream log_msg;

        if (!port_enable) {
            log_msg << "skip port not enabled " << port_desc.str();
            LOG(ERROR) << log_msg.str();
            continue;
        } else if (!port_lower_layers.length()) {
            log_msg << "skip port lower layer not configured " << port_desc.str();
            LOG(ERROR) << log_msg.str();
            continue;
        } else if (port_name.length() == 0) { // if name not available, get from lower layer
            // at this point lower layer has a non-zero length
            auto ssid_object = amxb_connection->get_object(port_lower_layers, 0, true);
            if (!ssid_object) {
                log_msg << "skip port unable to retrieve lower layer name " << port_desc.str();
                LOG(ERROR) << log_msg.str();
                continue;
            }
            std::string ssid_name;
            ssid_object->read_child<>(ssid_name, "Name");
            LOG(DEBUG) << "retrieved name " << ssid_name << " for " << port_desc.str();
            ifs.push_back(ssid_name);
        } else {
            LOG(DEBUG) << port_desc.str();
            ifs.push_back(port_name);
        }
    }

    return ifs;
}

} // namespace bpl
} // namespace beerocks
