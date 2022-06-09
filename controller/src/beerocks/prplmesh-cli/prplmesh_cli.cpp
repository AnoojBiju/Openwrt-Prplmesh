/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "prplmesh_cli.h"
#include "prplmesh_amx_client.h"

#include <arpa/inet.h>
#include <iostream>
#include <iterator>
#include <map>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace beerocks {
namespace prplmesh_api {

static prplmesh_cli::conn_map_t conn_map;
static std::string space = "";

prplmesh_cli::prplmesh_cli()
{
    m_amx_client = std::make_shared<beerocks::prplmesh_amx::AmxClient>();
    LOG_IF(!m_amx_client, FATAL) << "Unable to create ambiorix client instance!";

    LOG_IF(!m_amx_client->amx_initialize(AMBIORIX_BACKEND_PATH, AMBIORIX_BUS_URI), FATAL)
        << "Unable to connect to the ambiorix backend!";
}

bool prplmesh_cli::get_ip_from_iface(const std::string &iface, std::string &ip)
{
    int fd;
    struct ifreq ifr;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG(ERROR) << "Can't open SOCK_DGRAM socket.";
        return false;
    }

    //IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    // Get the address of the device using ifr_addr
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        LOG(ERROR) << "SIOCGIFADDR";
        close(fd);
        return false;
    }

    close(fd);
    ip = std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return true;
}

bool prplmesh_cli::print_radio(std::string device_path)
{
    std::string radio_path = device_path + "Radio.";
    std::string radio_path_i;
    amxc_var_t *device_obj = m_amx_client->get_object(device_path);

    conn_map.radio_number = GET_UINT32(device_obj, "RadioNumberOfEntries");

    for (uint32_t i = 1; i <= conn_map.radio_number; i++) {
        radio_path_i              = radio_path + std::to_string(i) + ".";
        std::string curr_op_class = radio_path_i + "CurrentOperatingClasses." + "*.";
        amxc_var_t *radio_obj     = m_amx_client->get_object(radio_path_i);
        amxc_var_t *op_class_obj  = m_amx_client->get_object(curr_op_class);
        conn_map.radio_id         = GET_CHAR(radio_obj, "ID");
        conn_map.bss_number       = GET_UINT32(radio_obj, "BSSNumberOfEntries");
        conn_map.channel          = GET_UINT32(op_class_obj, "Channel");

        //RADIO: wlan1-1 mac: 06:f0:21:90:d7:4b, ch: 1, bw: 20, freq: 2412MHz
        std::cout << space << "\tRADIO[" << i << "]: mac: " << conn_map.radio_id
                  << ", ch: " << conn_map.channel << ", bw: 20, freq: 2412MHz" << std::endl;

        for (uint32_t j = 1; j <= conn_map.bss_number; j++) {
            std::string bss_path = radio_path_i + "BSS." + std::to_string(j) + ".";
            std::string sta_path = bss_path + "STA.";
            amxc_var_t *bss_obj  = m_amx_client->get_object(bss_path);
            conn_map.bss_id      = GET_CHAR(bss_obj, "BSSID");
            conn_map.ssid        = GET_CHAR(bss_obj, "SSID");
            conn_map.sta_number  = GET_UINT32(bss_obj, "STANumberOfEntries");

            //      fVAP[0]: wlan1-1.0 bssid: 02:f0:21:90:d7:4b, ssid: prplmesh
            std::cout << space << "\t\tfVAP[" << j - 1 << "]: bssid: " << conn_map.bss_id
                      << ", ssid: " << conn_map.ssid << std::endl;

            for (uint32_t k = 0; k < conn_map.sta_number; k++) {
                std::string sta_path_i   = sta_path + std::to_string(k + 1) + ".";
                amxc_var_t *sta_obj      = m_amx_client->get_object(sta_path_i);
                std::string sta_mac      = GET_CHAR(sta_obj, "MACAddress");
                std::string sta_hostname = GET_CHAR(sta_obj, "Hostname");
                std::string sta_ipv4     = GET_CHAR(sta_obj, "IPV4Address");

                std::cout << space << "\t\t\tCLIENT[" << k << "]: mac: " << sta_mac
                          << " ipv4: " << sta_ipv4 << " name: " << sta_hostname << std::endl;
            }
        }
    }

    return true;
}

bool prplmesh_cli::print_device_info(std::string agent_mac, std::string skip_mac)
{
    std::string backhaul_device_id;

    for (uint32_t i = 1; i <= conn_map.device_number; i++) {
        std::string backhaul_path = "Device.WiFi.DataElements.Network.Device." + std::to_string(i) +
                                    ".MultiAPDevice.Backhaul.";
        amxc_var_t *backhaul_obj = m_amx_client->get_object(backhaul_path);
        backhaul_device_id       = GET_CHAR(backhaul_obj, "BackhaulDeviceID");
        std::string linktype     = GET_CHAR(backhaul_obj, "LinkType");

        if (linktype == "Ethernet" && backhaul_device_id == "" && agent_mac != skip_mac) {
            backhaul_device_id = conn_map.controller_id;
        }

        std::string curr_mac = GET_CHAR(backhaul_obj, "MACAddress");
        if (backhaul_device_id == agent_mac && skip_mac != curr_mac) {
            agent_mac = GET_CHAR(backhaul_obj, "MACAddress");
            std::string device_path =
                "Device.WiFi.DataElements.Network.Device." + std::to_string(i) + ".";
            space += "\t";
            std::cout << space << "Device[" << i << "]: name: Agent, mac: " << agent_mac
                      << " LinkType: " << linktype << std::endl;
            print_radio(device_path);
            print_device_info(agent_mac, "");
        }
    }

    if (backhaul_device_id != "") {
        // Need to decrease space value
        print_device_info(backhaul_device_id, agent_mac);
    }

    return true;
}

bool prplmesh_cli::prpl_conn_map(void)
{

    std::cout << "Start conn map" << std::endl;

    std::string network_path = "Device.WiFi.DataElements.Network.";
    amxc_var_t *network_obj  = m_amx_client->get_object(network_path);
    const char *op_band      = GET_CHAR(network_obj, "ControllerID");
    conn_map.device_number   = GET_UINT32(network_obj, "DeviceNumberOfEntries");

    conn_map.controller_id = std::string(op_band);

    std::cout << "Found " << conn_map.device_number << " devices" << std::endl;

    // Need to change br-lan to variable which depends on platform(rdkb/prplos)
    if (!prplmesh_cli::get_ip_from_iface("br-lan", conn_map.bridge_ip_v4)) {
        LOG(ERROR) << "Can't get bridge ip.";
    }

    // Print controller
    std::cout << "Device[1]: name: GW_MASTER, mac: " << conn_map.controller_id
              << ", ipv4: " << conn_map.bridge_ip_v4 << std::endl;

    // Print controller radios
    for (uint32_t i = 1; i <= conn_map.device_number; i++) {
        std::string device_path =
            "Device.WiFi.DataElements.Network.Device." + std::to_string(i) + ".";
        amxc_var_t *device_obj = m_amx_client->get_object(device_path);
        std::string device_id  = GET_CHAR(device_obj, "ID");

        // Find controller in all devices
        if (device_id == conn_map.controller_id) {
            print_radio(device_path);
            break;
        }
    }

    // Print all agents
    print_device_info(conn_map.controller_id, "");

    return true;
}

} // namespace prplmesh_api
} // namespace beerocks
