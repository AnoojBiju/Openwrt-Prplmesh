/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2023 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl_network/bpl_network.h>

#include <easylogging++.h>

#include <ambiorix_connection_manager.h>

using namespace beerocks::net;
using namespace beerocks::wbapi;

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
 * @brief get the path of a port for the given interface without specifying the bridge
 *
 * @param[in] iface  : name of the interface
 * @param[out] port  : full path of the port instance
*/
static bool get_bridge_port_path(const std::string &iface, std::string &port)
{
    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
    }
    std::string bridge_filter    = "Bridge.*.";
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

static bool disable_port(const std::string &port_object)
{
    return set_port_enable_state(port_object, false);
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

/**
 * @brief the easiest tr181 operation that produces the expected result is
 * disabling the corresponding bridge port
*/
bool bpl_network::remove_iface_from_bridge(const std::string &bridge, const std::string &iface)
{
    std::string interface_port_path;
    if (get_bridge_port_path(bridge, iface, interface_port_path)) {
        disable_port(interface_port_path);
        return true;
    }
    return false;
}

std::vector<std::string> bpl_network::get_bss_ifaces(const std::string &bss_iface,
                                                     const std::string &bridge_iface)
{
    if (bss_iface.empty()) {
        LOG(ERROR) << "bss_iface is empty!";
        return {};
    }
    if (bridge_iface.empty()) {
        LOG(ERROR) << "bridge_iface is empty!";
        return {};
    }

    auto ifaces_on_bridge = get_iface_list_from_bridge(bridge_iface);

    /**
     * Find all interfaces that their name contain the base bss name.
     * On upstream Hostapd the pattern is: "<bss_iface_name>.staN"
     * (e.g wlan0.0.sta1, wlan0.0.sta2 etc)
     * On MaxLinear platforms the pattern is: "bN_<bss_iface_name>"
     * (e.g b0_wlan0.0, b1_wlan0.0 etc).
     *
     * NOTE: If the VAP interface is wlan-long0.0, then the STA interface name will use an
     * abbreviated version b0_wlan-long0 instead of b0_wlan-long0.0.
     * It doesn't really work anyway because with that truncation, you may get conflicts between
     * wlan-long0.0 and wlan-lang0.1.
     */

    std::vector<std::string> bss_ifaces;
    for (const auto &iface : ifaces_on_bridge) {
        if (iface.find(bss_iface) != std::string::npos) {
            bss_ifaces.push_back(iface);
        }
    }
    return bss_ifaces;
}

bool bpl_network::iface_get_mac(const std::string &iface, std::string &mac)
{
    mac.clear();

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    std::string radio_filter    = "Device.WiFi.Radio.[Name == '" + iface + "'].";
    std::string ssid_filter     = "Device.WiFi.SSID.[Name == '" + iface + "'].";
    std::string eth_filter      = "Device.Ethernet.Interface.[Name == '" + iface + "'].";
    std::string eth_link_filter = "Device.Ethernet.Link.[Name == '" + iface + "'].";

    std::vector<std::string> iface_paths;

    if (!amxb_connection->resolve_path(radio_filter, iface_paths)) {
        if (!amxb_connection->resolve_path(ssid_filter, iface_paths)) {
            if (!amxb_connection->resolve_path(eth_link_filter, iface_paths)) {
                if (!amxb_connection->resolve_path(eth_filter, iface_paths)) {
                    LOG(ERROR) << "cannot retrieve the interface object corresponding to " << iface;
                    return false;
                }
            }
        }
    }
    // the only ordering in the above sequence is Radio before SSID

    // if we got here, at least one (and at most one) resolve path was successful
    mac = amxb_connection->get_param(iface_paths[0], "MACAddress")->get<std::string>();
    std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
    return true;
}

bool bpl_network::iface_get_ip(const std::string &iface, std::string &ip)
{
    ip.clear();

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    // first resolve: identify the IP.Interface and its first IP.Interface.IPv4Address instance;
    std::string ip_iface = "Device.IP.Interface.[Name == '" + iface + "'].";
    std::string ip_addr  = ip_iface + "IPv4Address.[IPAddress != '']";

    std::vector<std::string> ip_addr_paths;

    if (!amxb_connection->resolve_path(ip_addr, ip_addr_paths)) {
        LOG(ERROR) << "cannot retrieve ip addr object for " << iface;
        return false;
    }

    // if we got here, at least one (and at most one) resolve path was successful
    ip = amxb_connection->get_param(ip_addr_paths[0], "IPAddress")->get<std::string>();
    return true;
}

bool bpl_network::iface_get_name(const sMacAddr &mac, std::string &iface)
{
    // try to get matching MAC Address from either Device.WiFi.SSID or Device.Ethernet.Interface
    // resolve Device.WiFi.SSID.[MACAddress == mac]
    // resolve Device.Ethernet.Interface.[MACAddress == mac]
    // when used as [(mac) to (ethernet interface)] the function is not surjective, as several eth ports may
    // have the same MAC Address on certain boards

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    std::string mac_str = tlvf::mac_to_string(mac);

    //typically BSSIDs are lowercase, MACAddress-es are uppercase
    std::transform(mac_str.begin(), mac_str.end(), mac_str.begin(), ::toupper);

    LOG(DEBUG) << "get iface name by mac " << mac_str;

    std::string ssid_filter = "Device.WiFi.SSID.[MACAddress == '" + mac_str + "'].";
    std::string eth_filter  = "Device.Ethernet.Interface.[MACAddress == '" + mac_str + "'].";

    std::vector<std::string> iface_paths;

    if (!amxb_connection->resolve_path(ssid_filter, iface_paths)) {
        if (!amxb_connection->resolve_path(eth_filter, iface_paths)) {
            LOG(ERROR) << "can't retrieve the interface object corresponding to " << mac_str;
            return false;
        }
    }
    // if we got here, at least one (and at most one) resolve path was successful
    iface = amxb_connection->get_param(iface_paths[0], "Name")->get<std::string>();
    return true;
}

bool bpl_network::iface_get_host_bridge(const std::string &iface, std::string &bridge)
{

    bridge.clear();

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    std::string port_path;
    get_bridge_port_path(iface, port_path);
    // returns a string Device.Bridging.Bridge.x.Port.y.
    // the useful information here is X;
    // to get bridge name, replace y with 1 and read the name
    // from the management port

    if (port_path.back() == '.') {
        port_path.pop_back();
    } // remove trailing '.' if any

    auto pos = port_path.rfind('.');
    if (pos == std::string::npos) {
        LOG(ERROR) << "malformed path " << port_path;
        return false;
    }
    auto management_port = port_path.substr(0, pos) + ".1.";

    bridge = amxb_connection->get_param(management_port, "Name")->get<std::string>();

    return true;
}

/**
 * @brief : typically this function is used with a bridge name as parameter;
 * the search path is as follows:
 * ip_iface = Device.IP.Interface.[Name == @param[in] iface_name].
 * ip = ip_iface.IPv4Address.[first non-empty IPAddress].IPAddress
 * netmask = ip_iface.IPv4Address.[first non-empty IPAddress].SubnetMask
 * mac = ip_iface.LowerLayers.MACAddress (LowerLayers is an Device.Ethernet.Link)
 * gw = ip_iface.Router.GatewayIPAddress
*/
bool bpl_network::get_iface_info(network_utils::iface_info &info, const std::string &iface_name)
{
    // for the ip address, the code is written as if there is only one IP address possible for
    // one interface
    info.iface = iface_name;
    info.mac.clear();
    info.ip.clear();
    info.netmask.clear();
    info.ip_gw.clear();
    // it's unclear where the ip_gw is later used, but it is retrieved in the datamodel
    // under Device.Routing
    // example
    // Device.Routing.Router.1.IPv4Forwarding.4.GatewayIPAddress=""
    // Device.Routing.Router.1.IPv4Forwarding.4.Interface="br-lan"

    AmbiorixConnectionSmartPtr amxb_connection = AmbiorixConnectionManager::get_connection();
    if (!amxb_connection) {
        LOG(ERROR) << "can't retrieve connection to amxb bus";
        return false;
    }

    // first resolve: identify the IP.Interface and its first IP.Interface.IPv4Address instance;
    std::string ip_iface = "Device.IP.Interface.[Name == '" + iface_name + "'].";
    std::string ip_addr  = ip_iface + "IPv4Address.[IPAddress != '']";

    std::vector<std::string> ip_iface_paths, ip_addr_paths;
    if (!amxb_connection->resolve_path(ip_iface, ip_iface_paths)) {
        LOG(ERROR) << "cannot retrieve ip interface object for " << iface_name;
        return false;
    }
    if (!amxb_connection->resolve_path(ip_addr, ip_addr_paths)) {
        LOG(ERROR) << "cannot retrieve ip addr object for " << iface_name;
        return false;
    }

    // second resolve : get IP.Interface.LowerLayers and identify the routing rule for the given
    // interface
    std::string lower_layer =
        amxb_connection->get_param(ip_iface_paths[0], "LowerLayers")->get<std::string>();
    std::string router =
        amxb_connection->get_param(ip_iface_paths[0], "Router")->get<std::string>();

    std::string fwd_rule = router + "IPv4Forwarding.[Interface =='" + iface_name + "'].";
    std::vector<std::string> fwding_rules;
    if (!amxb_connection->resolve_path(fwd_rule, fwding_rules)) {
        LOG(ERROR) << "cannot retrieve forwarding rules for " << router << " with rules "
                   << fwd_rule;
        return false;
    }
    LOG(INFO) << "found " << lower_layer << " "
              << " router " << router << " " << fwd_rule << " " << ip_addr_paths[0];

    // fill output
    info.mac     = amxb_connection->get_param(lower_layer, "MACAddress")->get<std::string>();
    info.ip      = amxb_connection->get_param(ip_addr_paths[0], "IPAddress")->get<std::string>();
    info.netmask = amxb_connection->get_param(ip_addr_paths[0], "SubnetMask")->get<std::string>();
    info.ip_gw =
        amxb_connection->get_param(fwding_rules[0], "GatewayIPAddress")->get<std::string>();

    std::stringstream ss;
    ss << "br-lan mac " << info.mac << " info.ip " << info.ip << " netmask " << info.netmask
       << " gw_ip " << info.ip_gw;

    LOG(DEBUG) << ss.str();
    return true;
}

} // namespace bpl
} // namespace beerocks
