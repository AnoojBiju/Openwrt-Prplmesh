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

bool prplmesh_cli::prpl_conn_map(void)
{
    conn_map_t conn_map;

    std::cout << "Start conn map" << std::endl;

    // GW_BRIDGE: name: GW_MASTER, mac: d8:58:d7:01:47:16, ipv4: 192.168.1.1
    std::string network_path = "Device.WiFi.DataElements.Network.";
    amxc_var_t *network_obj  = m_amx_client->get_object(network_path);
    const char *op_band      = GET_CHAR(network_obj, "ControllerID");

    conn_map.controller_id = std::string(op_band);

    // Need to change br-lan to variable which depends on platform(rdkb/prplos)
    if (!prplmesh_cli::get_ip_from_iface("br-lan", conn_map.bridge_ip_v4)) {
        LOG(ERROR) << "Can't get bridge ip.";
    }

    std::cout << "GW_BRIDGE: name: GW_MASTER, mac: " << conn_map.controller_id
              << ", ipv4: " << conn_map.bridge_ip_v4 << std::endl;

    // we use only device 1. Need it to get radio numbers
    std::string device_path = network_path + "Device.1.";
    std::string radio_path  = device_path + "Radio.";
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
        std::cout << "\t RADIO[" << i << "]: mac: " << conn_map.radio_id
                  << ", ch: " << conn_map.channel << ", bw: 20, freq: 2412MHz" << std::endl;

        for (uint32_t j = 1; j <= conn_map.bss_number; j++) {
            std::string bss_path = radio_path_i + "BSS." + std::to_string(j) + ".";
            std::string sta_path = bss_path + "STA.";
            amxc_var_t *bss_obj  = m_amx_client->get_object(bss_path);
            conn_map.bss_id      = GET_CHAR(bss_obj, "BSSID");
            conn_map.ssid        = GET_CHAR(bss_obj, "SSID");
            conn_map.sta_number  = GET_UINT32(bss_obj, "STANumberOfEntries");

            //      fVAP[0]: wlan1-1.0 bssid: 02:f0:21:90:d7:4b, ssid: prplmesh
            std::cout << "\t\t fVAP[" << j - 1 << "]: bssid: " << conn_map.bss_id
                      << ", ssid: " << conn_map.ssid << std::endl;

            for (uint32_t k = 0; k < conn_map.sta_number; k++) {
                std::string sta_path_i = sta_path + std::to_string(k + 1) + ".";
                amxc_var_t *sta_obj    = m_amx_client->get_object(sta_path_i);
                std::string sta_mac    = GET_CHAR(sta_obj, "MACAddress");

                std::cout << "\t\t\t CLIENT[" << k << "]: mac: " << sta_mac << std::endl;
            }
        }
    }

    return true;
}

} // namespace prplmesh_api
} // namespace beerocks
