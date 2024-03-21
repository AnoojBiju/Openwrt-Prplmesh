/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "prplmesh_cli.h"
#include "prplmesh_amx_client.h"

#include "bml_utils.h"

#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <beerocks/tlvf/beerocks_message.h>
#include <easylogging++.h>
#include <mapf/common/utils.h>

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
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface.c_str());

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

int prplmesh_cli::start_dcs_single_scan(const std::string &radio_mac, int32_t dwell_time,
                                        const std::string &channel_pool)
{
    std::cout << "start_dcs_single_scan, mac=" << radio_mac << ", dwell_time=" << dwell_time
              << ", channel_pool=" << channel_pool << std::endl;

    if (dwell_time < 0) {
        std::cout << __func__ << ", invalid input: dwell_time='" << dwell_time << "'."
                  << " Only positive values are supported!" << std::endl;
        return -1;
    }

    if (channel_pool.length() == 0) {
        std::cout << __func__
                  << "invalid channel_pool input: channel_pool.length()==" << channel_pool.length()
                  << std::endl;
        return -1;
    }

    auto channels      = string_utils::str_split(channel_pool, ',');
    auto channels_size = channels.size();

    if (channels_size > BML_CHANNEL_SCAN_MAX_CHANNEL_POOL_SIZE) {
        std::cout << "size of channel_pool is too big. size=" << channels_size << std::endl;
        return -1;
    }

    unsigned int channel_pool_arr[BML_CHANNEL_SCAN_MAX_CHANNEL_POOL_SIZE] = {0};

    for (size_t i = 0; i < channels_size; i++) {
        channel_pool_arr[i] = beerocks::string_utils::stoi(channels[i]);
    }

    bml_start_dcs_single_scan(ctx, radio_mac.c_str(), dwell_time, uint32_t(channels_size),
                              channel_pool_arr);
    return 0;
}

int prplmesh_cli::get_dcs_scan_results(const std::string &radio_mac, uint32_t max_results_size,
                                       bool is_single_scan)
{
    std::cout << __func__ << ", mac=" << radio_mac << ", max_results_size=" << max_results_size
              << ", is_single_scan=" << string_utils::bool_str(is_single_scan) << std::endl;

    if (max_results_size == 0) {
        std::cout << __func__ << "invalid input, max_results_size==0" << std::endl;
        return -1;
    }

    BML_NEIGHBOR_AP results[max_results_size];

    uint8_t status             = 0;
    unsigned int results_count = max_results_size;
    int ret = bml_get_dcs_scan_results(ctx, radio_mac.c_str(), results, &results_count, &status,
                                       is_single_scan);

    if (ret == BML_RET_OK) {
        if (results_count > max_results_size) {
            std::cout << __func__ << "ERROR: results_count(" << results_count << ")"
                      << " > max_results_size(" << max_results_size << ")" << std::endl;
        } else if ((status == 0) && (results_count > 0)) {
            for (size_t i = 0; i < results_count; i++) {
                auto res = results[i];
                std::cout << "result[" << i << "]:" << std::endl
                          << "  ssid=" << res.ap_SSID << std::endl
                          << "  bssid=" << tlvf::mac_to_string(res.ap_BSSID) << std::endl
                          << "  mode=" << int(res.ap_Mode) << std::endl
                          << "  channel=" << int(res.ap_Channel) << std::endl
                          << "  signal_strength_dbm=" << res.ap_SignalStrength << std::endl
                          << "  security_mode_enabled="
                          << string_from_int_array(res.ap_SecurityModeEnabled,
                                                   BML_CHANNEL_SCAN_ENUM_LIST_SIZE)
                          << std::endl
                          << "  encryption_mode="
                          << string_from_int_array(res.ap_EncryptionMode,
                                                   BML_CHANNEL_SCAN_ENUM_LIST_SIZE)
                          << std::endl
                          << "  operating_frequency_band=" << int(res.ap_OperatingFrequencyBand)
                          << std::endl
                          << "  supported_standards="
                          << string_from_int_array(res.ap_SupportedStandards,
                                                   BML_CHANNEL_SCAN_ENUM_LIST_SIZE)
                          << std::endl
                          << "  operating_standards=" << int(res.ap_OperatingStandards) << std::endl
                          << "  operating_channel_bandwidth="
                          << int(res.ap_OperatingChannelBandwidth) << std::endl
                          << "  beacon_period_ms=" << int(res.ap_BeaconPeriod) << std::endl
                          << "  noise_dbm=" << int(res.ap_Noise) << std::endl
                          << "  basic_data_transfer_rates_kbps="
                          << string_from_int_array(res.ap_BasicDataTransferRates,
                                                   BML_CHANNEL_SCAN_ENUM_LIST_SIZE)
                          << std::endl
                          << "  supported_data_transfer_rates_kbps="
                          << string_from_int_array(res.ap_SupportedDataTransferRates,
                                                   BML_CHANNEL_SCAN_ENUM_LIST_SIZE)
                          << std::endl
                          << "  dtim_period=" << int(res.ap_DTIMPeriod) << std::endl
                          << "  channel_utilization=" << int(res.ap_ChannelUtilization) << std::endl
                          << "  station_count=" << int(res.ap_StationCount) << std::endl;
            }
        }
    }

    return 0;
}

int prplmesh_cli::get_device_operational_radios(const std::string &al_mac)
{
    BML_DEVICE_DATA device_data = {};
    device_data.al_mac          = al_mac.c_str();

    int ret = bml_device_oper_radios_query(ctx, &device_data);

    // Main agent
    std::cout << ((ret == BML_RET_OK) ? "OK" : "FAIL") << " Main radio agent operational"
              << std::endl;
    for (const auto &radio : device_data.radios) {
        if (radio.is_connected) {
            // wlan radio agents
            std::cout << (radio.is_operational ? "OK " : "FAIL ") << radio.iface_name
                      << " radio agent operational" << std::endl;
        }
    }

    return 0;
}

bool prplmesh_cli::connect()
{
    beerocks_conf_path = mapf::utils::get_install_path() + "config";
    const char *c      = beerocks_conf_path.c_str();
    bml_connect(&ctx, c, this);
    return true;
}

void prplmesh_cli::disconnect() {}

float prplmesh_cli::get_freq_from_class(const uint32_t oper_class)
{
    float freq;

    if ((oper_class >= 1 && oper_class <= 5)) {
        freq = 0.902;
    } else if (oper_class == 6 || oper_class == 17 || oper_class == 19 ||
               (oper_class >= 66 && oper_class <= 67)) {
        freq = 0.863;
    } else if (oper_class == 8 || oper_class == 73) {
        freq = 0.9165;
    } else if ((oper_class >= 14 && oper_class <= 16) || (oper_class >= 73 && oper_class <= 76)) {
        freq = 0.9175;
    } else if (oper_class == 18 || (oper_class >= 20 && oper_class <= 29) ||
               (oper_class >= 68 && oper_class <= 72)) {
        freq = 0.902;
    } else if (oper_class == 30 || oper_class == 77) {
        freq = 0.9014;
    } else if (oper_class == 81 || oper_class == 83 || oper_class == 84) {
        freq = 2.407;
    } else if (oper_class == 82) {
        freq = 2.414;
    } else if ((oper_class >= 94 && oper_class <= 95) || (oper_class >= 109 && oper_class <= 110)) {
        freq = 3.00;
    } else if (oper_class == 96) {
        freq = 3.0025;
    } else if (oper_class == 101) {
        freq = 4.85;
    } else if (oper_class == 102) {
        freq = 4.89;
    } else if (oper_class == 103) {
        freq = 4.9375;
    } else if (oper_class >= 104 && oper_class <= 107) {
        freq = 4.00;
    } else if (oper_class == 108 || oper_class == 111) {
        freq = 4.0025;
    } else if (oper_class >= 115 && oper_class <= 130) {
        freq = 5.00;
    } else if (oper_class >= 131 && oper_class <= 136) {
        freq = 6.00;
    } else if (oper_class >= 180 && oper_class <= 181) {
        freq = 56.16;
    } else if (oper_class == 182) {
        freq = 56.70;
    } else if (oper_class == 183) {
        freq = 42.66;
    } else if (oper_class == 184) {
        freq = 47.52;
    } else if (oper_class == 185) {
        freq = 42.93;
    } else if (oper_class == 186) {
        freq = 47.79;
    } else {
        freq = 0.00;
    }

    return freq;
}

bool prplmesh_cli::print_radio(std::string device_path)
{
    std::string radio_ht_path     = device_path + "Radio.*.";
    const amxc_htable_t *ht_radio = m_amx_client->get_htable_object(radio_ht_path);
    int radio_index               = 1;

    amxc_htable_iterate(radio_it, ht_radio)
    {
        const char *radio_key     = amxc_htable_it_get_key(radio_it);
        std::string radio_path_i  = std::string(radio_key);
        amxc_var_t *radio_obj     = amxc_var_from_htable_it(radio_it);
        std::string curr_op_class = radio_path_i + "CurrentOperatingClasses." + "*.";
        amxc_var_t *op_class_obj  = m_amx_client->get_object(curr_op_class);
        conn_map.radio_id         = GET_CHAR(radio_obj, "ID");
        conn_map.channel          = GET_UINT32(op_class_obj, "Channel");
        conn_map.oper_class       = GET_UINT32(op_class_obj, "Class");
        float freq                = get_freq_from_class(conn_map.oper_class);

        // RADIO: wlan1-1 mac: 06:f0:21:90:d7:4b, ch: 1, bw: 20, freq: 2412MHz
        std::cout << space << "\tRADIO[" << radio_index << "]: mac: " << conn_map.radio_id
                  << ", ch: " << conn_map.channel << ", freq: " << freq << "GHz" << std::endl;

        std::string bss_ht_path     = radio_path_i + "BSS.*.";
        const amxc_htable_t *ht_bss = m_amx_client->get_htable_object(bss_ht_path);
        int vap_index               = 0;

        amxc_htable_iterate(bss_it, ht_bss)
        {
            const char *bss_key    = amxc_htable_it_get_key(bss_it);
            std::string bss_path_i = std::string(bss_key);
            amxc_var_t *bss_obj    = amxc_var_from_htable_it(bss_it);
            conn_map.bss_id        = GET_CHAR(bss_obj, "BSSID");
            conn_map.ssid          = GET_CHAR(bss_obj, "SSID");

            // VAP[0]: wlan1-1.0 bssid: 02:f0:21:90:d7:4b, ssid: prplmesh
            std::cout << space << "\t\tVAP[" << vap_index << "]: bssid: " << conn_map.bss_id
                      << ", ssid: " << conn_map.ssid << std::endl;

            std::string sta_ht_path     = bss_path_i + "STA.*.";
            const amxc_htable_t *ht_sta = m_amx_client->get_htable_object(sta_ht_path);
            int sta_index               = 1;
            amxc_htable_iterate(sta_it, ht_sta)
            {
                amxc_var_t *sta_obj      = amxc_var_from_htable_it(sta_it);
                std::string sta_mac      = GET_CHAR(sta_obj, "MACAddress");
                std::string sta_hostname = GET_CHAR(sta_obj, "Hostname");
                std::string sta_ipv4     = GET_CHAR(sta_obj, "IPV4Address");

                std::cout << space << "\t\t\tCLIENT[" << sta_index << "]: name: " << sta_hostname
                          << " mac: " << sta_mac << " ipv4: " << sta_ipv4 << std::endl;
                sta_index++;
            }
            vap_index++;
        }
        radio_index++;
    }
    return true;
}

bool prplmesh_cli::print_device_info(std::string agent_mac, std::string skip_mac)
{
    std::string backhaul_device_id;
    std::string device_ht_path     = CONTROLLER_ROOT_DM ".Network.Device.*.";
    const amxc_htable_t *ht_device = m_amx_client->get_htable_object(device_ht_path);

    amxc_htable_iterate(device_it, ht_device)
    {
        std::string device_path_i = amxc_htable_it_get_key(device_it);
        std::string backhaul_path = device_path_i + ".MultiAPDevice.Backhaul.";
        amxc_var_t *backhaul_obj  = m_amx_client->get_object(backhaul_path);
        backhaul_device_id        = GET_CHAR(backhaul_obj, "BackhaulDeviceID");
        std::string linktype      = GET_CHAR(backhaul_obj, "LinkType");

        if (linktype == "Ethernet" && backhaul_device_id.empty() && agent_mac != skip_mac) {
            backhaul_device_id = conn_map.controller_id;
        }

        std::string curr_mac = GET_CHAR(backhaul_obj, "MACAddress");

        if (backhaul_device_id == agent_mac && skip_mac != curr_mac) {
            agent_mac = GET_CHAR(backhaul_obj, "MACAddress");
            space += "\t";
            conn_map.device_index++;
            std::cout << space << "Device[" << conn_map.device_index
                      << "]: name: Agent, mac: " << agent_mac << " LinkType: " << linktype
                      << std::endl;
            print_radio(device_path_i);
            print_device_info(agent_mac, "");
        }
    }

    if (conn_map.device_index < conn_map.device_number) {
        // Decrease space value
        if (space.size() > 0) {
            space.pop_back();
        }

        //Go to the previous primary device but skip the current one
        if (backhaul_device_id.empty()) {
            print_device_info(conn_map.controller_id, agent_mac);
        } else {
            print_device_info(backhaul_device_id, agent_mac);
        }
    }

    return true;
}

bool prplmesh_cli::prpl_conn_map()
{

    std::cout << "Start conn map" << std::endl;

    std::string network_path = CONTROLLER_ROOT_DM ".Network.";
    amxc_var_t *network_obj  = m_amx_client->get_object(network_path);
    conn_map.controller_id   = GET_CHAR(network_obj, "ControllerID");
    conn_map.device_number   = GET_UINT32(network_obj, "DeviceNumberOfEntries");

    std::cout << "Found " << conn_map.device_number << " devices" << std::endl;

    // Need to change br-lan to variable which depends on platform(rdkb/prplos)
    if (!prplmesh_cli::get_ip_from_iface("br-lan", conn_map.bridge_ip_v4)) {
        LOG(ERROR) << "Can't get bridge ip.";
    }

    // Print controller
    std::cout << "Device[1]: name: GW_MASTER, mac: " << conn_map.controller_id
              << ", ipv4: " << conn_map.bridge_ip_v4 << std::endl;

    // Print controller radios
    const amxc_htable_t *devices = m_amx_client->get_htable_object(conn_map.device_ht_path);

    amxc_htable_iterate(device_it, devices)
    {
        const char *key         = amxc_htable_it_get_key(device_it);
        std::string device_path = std::string(key);
        amxc_var_t *device_obj  = amxc_var_from_htable_it(device_it);
        std::string device_id   = GET_CHAR(device_obj, "ID");

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

void prplmesh_cli::print_help()
{
    std::cerr << R"help!(
Usage: prplmesh_cli OPTION or
Usage: prplmesh_cli -c <command> [command_arguments]
The following options are available:
-v	: prints the current prplMesh version
-h	: prints this help text

The following commands are available :
help      		: get supported commands
version   		: get current prplMesh version
show_ap   		: show AccessPoints
set_ssid  		: set SSID
  -o .<ap_object_number>|<ap_ssid>	Use .. if <ap_ssid> starts with .
  -n <new_ssid_name>
set_security		: set security
  -o .<ap_object_number>|<ap_ssid>	Same as for set_ssid
  -m None|WPA2-Personal
  -p <passphrase>			For the WPA2-Personal mode
conn_map  		: dump the latest network map
)help!";
}

void prplmesh_cli::print_version()
{
    std::cerr << "prplMesh version: " << BEEROCKS_VERSION << std::endl;
}

std::string prplmesh_cli::get_ap_path(std::string ap)
{
    std::stringstream path;
    path << CONTROLLER_ROOT_DM << ".Network.AccessPoint.";

    if (ap[0] == '.' and ap[1] != '.') {
        path << ap.substr(1) << '.';
        return path.str();
    }

    if (ap[0] == '.' and ap[1] == '.') {
        ap = ap.substr(1);
    }

    std::string ap_ht_path     = path.str() + "*.";
    const amxc_htable_t *ht_ap = m_amx_client->get_htable_object(ap_ht_path);
    amxc_htable_iterate(ap_it, ht_ap)
    {
        std::string ap_path_i = amxc_htable_it_get_key(ap_it);
        amxc_var_t *ap_obj    = m_amx_client->get_object(ap_path_i);
        std::string ap_ssid   = GET_CHAR(ap_obj, "SSID");

        if (strcasecmp(ap.c_str(), ap_ssid.c_str()) == 0) {
            return ap_path_i;
        }
    }

    return "";
}

void prplmesh_cli::show_ap()
{
    std::cout << "Show AccessPoints:" << std::endl;
    std::string ap_ht_path     = CONTROLLER_ROOT_DM ".Network.AccessPoint.*.";
    const amxc_htable_t *ht_ap = m_amx_client->get_htable_object(ap_ht_path);
    if (!ht_ap) {
        // No access points defined?
        // Or error retrieving object?
        std::cerr << "Unable to access object at path " << ap_ht_path << std::endl;
        return;
    }
    auto flags = std::cout.flags();
    boolalpha(std::cout);
    int ap_index = 0;
    amxc_htable_iterate(ap_it, ht_ap)
    {
        ap_index++;
        std::string ap_path_i = amxc_htable_it_get_key(ap_it);
        amxc_var_t *ap_obj    = m_amx_client->get_object(ap_path_i);
        // AP[1]: ssid: PrplCli, MultiApMode: Fronthaul
        //     Band 2.4G: true, Band 5G-L: true, Band 5G-H: true, Band 6G: false
        std::cout << "AP[" << ap_index << "]:";
        std::string ap_ssid = GET_CHAR(ap_obj, "SSID");
        std::cout << " ssid: " << ap_ssid;
        std::string ap_multi_ap_mode = GET_CHAR(ap_obj, "MultiApMode");
        std::cout << ", MultiAPMode: " << ap_multi_ap_mode << std::endl;
        std::cout << "    Band 2.4G: " << GET_BOOL(ap_obj, "Band2_4G");
        std::cout << ", Band 5G-L: " << GET_BOOL(ap_obj, "Band5GL");
        std::cout << ", Band 5G-H: " << GET_BOOL(ap_obj, "Band5GH");
        std::cout << ", Band 6G: " << GET_BOOL(ap_obj, "Band6G") << std::endl;
    }
    std::cout.flags(flags);
    if (ap_index == 0) {
        std::cout << "(None defined)" << std::endl;
    }
}

bool prplmesh_cli::set_ssid(const std::string &ap, const std::string &ssid)
{
    std::string ap_path = get_ap_path(ap);
    if (ap_path.empty()) {
        std::cerr << "No AP found with id " << ap << std::endl;
        return false;
    }

    amxc_var_t *ap_obj = m_amx_client->get_object(ap_path);
    if (!ap_obj) {
        std::cerr << "Unable to access object at path " << ap_path << std::endl;
        return false;
    }

    amxc_var_set(cstring_t, GET_ARG(ap_obj, "SSID"), ssid.c_str());
    auto status = m_amx_client->set_object(ap_path, ap_obj);

    if (status != AMXB_STATUS_OK) {
        std::cerr << "Setting new SSID failed with: " << amxb_get_error(status) << std::endl;
    } else {
        std::cerr << "Successfully set " << ap_path << " SSID to " << ssid << std::endl;
    }

    return status == AMXB_STATUS_OK;
}

bool prplmesh_cli::set_security(const std::string &ap, const std::string &mode,
                                const std::string &passphrase)
{
    std::string ap_path = get_ap_path(ap);
    if (ap_path.empty()) {
        std::cerr << "No AP found with id " << ap << std::endl;
        return false;
    }

    amxc_var_t *ap_obj = m_amx_client->get_object(ap_path += "Security.");
    if (!ap_obj) {
        std::cerr << "Unable to access object at path " << ap_path << std::endl;
        return false;
    }

    amxc_var_set(cstring_t, GET_ARG(ap_obj, "ModeEnabled"), mode.c_str());
    auto status = m_amx_client->set_object(ap_path, ap_obj, ap_obj);
    if (status != AMXB_STATUS_OK) {
        std::cerr << "Changing security params failed with: " << amxb_get_error(status) << '\n';
        return false;
    }

    if (mode == "WPA2-Personal") {
        ap_obj = amxc_var_get_first(amxc_var_get_first(ap_obj));
        if (GET_ARG(ap_obj, "KeyPassphrase")) {
            amxc_var_set(cstring_t, GET_ARG(ap_obj, "KeyPassphrase"), passphrase.c_str());
        } else {
            amxc_var_add_key(cstring_t, ap_obj, "KeyPassphrase", passphrase.c_str());
        }
        status = m_amx_client->set_object(ap_path, ap_obj, ap_obj);
    }

    if (status != AMXB_STATUS_OK) {
        std::cerr << "Changing security params failed with: " << amxb_get_error(status) << '\n';
    } else {
        std::cerr << "Successfully set " << ap_path << " params" << std::endl;
    }

    return status == AMXB_STATUS_OK;
}

template <typename T>
const std::string prplmesh_cli::string_from_int_array(T *arr, size_t arr_max_size)
{
    std::stringstream ss;
    if (arr) {
        for (size_t i = 0; i < arr_max_size; i++) {
            ss << ((i != 0) ? ", " : "") << (unsigned int)(arr[i]);
        }
    }
    return ss.str();
}

} // namespace prplmesh_api
} // namespace beerocks
