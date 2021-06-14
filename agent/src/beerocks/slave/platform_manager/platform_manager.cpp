/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "platform_manager.h"

#include "../agent_db.h"

#include <bcl/network/network_utils.h>
#include <bcl/network/sockets_impl.h>
#include <bcl/transaction.h>
#include <easylogging++.h>

#include <beerocks/tlvf/beerocks_message.h>
#include <beerocks/tlvf/beerocks_message_platform.h>

#include <bpl/bpl_dhcp.h>

#include <net/if.h> // if_nametoindex

namespace beerocks {

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

static const uint8_t s_arrZeroMac[]  = {0, 0, 0, 0, 0, 0};
static const uint8_t s_arrBCastMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define ARP_NOTIF_INTERVAL (90000)                  // 1.5 minutes
#define ARP_CLEAN_INTERVAL (ARP_NOTIF_INTERVAL * 2) // 2 notif. intervals

/**
 * Time interval to periodically clean old ARP table entries.
 */
constexpr std::chrono::milliseconds clean_old_arp_entries_timer_interval(ARP_CLEAN_INTERVAL);

/**
 * Time interval to periodically check if WLAN parameters have changed.
 */
constexpr std::chrono::milliseconds check_wlan_params_changed_timer_interval(5000);

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////
inline bwl::WiFiSec platform_to_bwl_security(const std::string &sec)
{
    if (!sec.compare("None")) {
        return bwl::WiFiSec::None;
    } else if (!sec.compare("WEP-64")) {
        return bwl::WiFiSec::WEP_64;
    } else if (!sec.compare("WEP-128")) {
        return bwl::WiFiSec::WEP_128;
    } else if (!sec.compare("WPA-Personal")) {
        return bwl::WiFiSec::WPA_PSK;
    } else if (!sec.compare("WPA2-Personal")) {
        return bwl::WiFiSec::WPA2_PSK;
    } else if (!sec.compare("WPA-WPA2-Personal")) {
        return bwl::WiFiSec::WPA_WPA2_PSK;
    } else {
        return bwl::WiFiSec::Invalid;
    }
}

static beerocks::eFreqType bpl_band_to_freq_type(int bpl_band)
{
    if (bpl_band == BPL_RADIO_BAND_2G) {
        return beerocks::eFreqType::FREQ_24G;
    } else if (bpl_band == BPL_RADIO_BAND_5G) {
        return beerocks::eFreqType::FREQ_5G;
    } else if (bpl_band == BPL_RADIO_BAND_AUTO) {
        return beerocks::eFreqType::FREQ_AUTO;
    } else {
        return beerocks::eFreqType::FREQ_UNKNOWN;
    }
}

static bool fill_platform_settings(
    const std::string &iface_name,
    std::unordered_map<std::string, std::shared_ptr<beerocks_message::sWlanSettings>>
        &iface_wlan_params_map)
{
    auto db = AgentDB::get();

    char security_type[beerocks::message::WIFI_SECURITY_TYPE_MAX_LENGTH];
    if (bpl::cfg_get_beerocks_credentials(BPL_RADIO_FRONT, db->device_conf.front_radio.ssid,
                                          db->device_conf.front_radio.pass, security_type) < 0) {
        LOG(ERROR) << "Failed reading front Wi-Fi credentials!";
        return false;
    }
    db->device_conf.front_radio.security_type = platform_to_bwl_security(security_type);

    LOG(DEBUG) << "Front Credentials:"
               << " ssid=" << db->device_conf.front_radio.ssid
               << " sec=" << db->device_conf.front_radio.security_type << " pass=***";

    char ssid[beerocks::message::WIFI_SSID_MAX_LENGTH];
    char pass[beerocks::message::WIFI_PASS_MAX_LENGTH];
    if (bpl::cfg_get_beerocks_credentials(BPL_RADIO_BACK, ssid, pass, security_type) < 0) {
        LOG(ERROR) << "Failed reading Wi-Fi back credentials!";
        return false;
    }
    db->device_conf.back_radio.ssid = std::string(ssid, beerocks::message::WIFI_SSID_MAX_LENGTH);
    db->device_conf.back_radio.pass = std::string(pass, beerocks::message::WIFI_PASS_MAX_LENGTH);
    db->device_conf.back_radio.security_type = platform_to_bwl_security(security_type);

    int mem_only_psk = bpl::cfg_get_security_policy();
    if (mem_only_psk < 0) {
        LOG(ERROR) << "Failed reading Wi-Fi security policy!";
        return false;
    }

    db->device_conf.back_radio.mem_only_psk = bool(mem_only_psk);

    LOG(DEBUG) << "Back Credentials:"
               << " ssid=" << db->device_conf.back_radio.ssid
               << " sec=" << db->device_conf.back_radio.security_type
               << " mem_only_psk=" << db->device_conf.back_radio.mem_only_psk << " pass=***";

    bpl::BPL_WLAN_PARAMS params;
    if (bpl::cfg_get_wifi_params(iface_name.c_str(), &params) < 0) {
        LOG(ERROR) << "Failed reading '" << iface_name << "' parameters!";
        return false;
    }
    /* update message */
    db->device_conf.front_radio.config[iface_name].band_enabled       = params.enabled;
    db->device_conf.front_radio.config[iface_name].configured_channel = params.channel;
    db->device_conf.front_radio.config[iface_name].sub_band_dfs       = params.sub_band_dfs;

    // although this will update the same variable again and again for each radio,
    // and the final value will be of the latest radio. We still expect them all
    // to have the same value as this is a country code. Although technically possible by the code,
    // we don't expect the same agent exists in two different countries at the same time.
    // verificartioation is done for logging only
    CountryCode current_country;
    current_country[0] = params.country_code[0];
    current_country[1] = params.country_code[1];

    bool db_country_code_empty =
        (db->device_conf.country_code[0] == 0) && (db->device_conf.country_code[1] == 0);

    if (current_country != db->device_conf.country_code && !db_country_code_empty) {
        LOG(ERROR) << "strangely enough this agent exists in more than one country: "
                   << current_country[0] << current_country[1] << " and "
                   << db->device_conf.country_code[0] << db->device_conf.country_code[1];
    }
    // take the latest
    db->device_conf.country_code = current_country;

    LOG(DEBUG) << "wlan settings " << iface_name << ":";
    LOG(DEBUG) << "band_enabled=" << params.enabled;
    LOG(DEBUG) << "channel=" << params.channel;
    LOG(DEBUG) << "sub_band_dfs=" << params.sub_band_dfs;
    LOG(DEBUG) << "country-code=" << db->device_conf.country_code[0]
               << db->device_conf.country_code[1];

    // initialize wlan params cache
    //erase interface cache from map if exists
    iface_wlan_params_map.erase(iface_name);
    auto params_ptr = std::make_shared<beerocks_message::sWlanSettings>();
    if (!params_ptr) {
        LOG(ERROR) << "Failed creating shared pointer";
        return false;
    }

    params_ptr->band_enabled = params.enabled;
    params_ptr->channel      = params.channel;

    iface_wlan_params_map[iface_name] = params_ptr;

    LOG(DEBUG) << "iface=" << iface_name << " added to wlan params change check";

    const int back_vaps_buff_len =
        BPL_BACK_VAPS_GROUPS * BPL_BACK_VAPS_IN_GROUP * BPL_MAC_ADDR_OCTETS_LEN;
    char back_vaps[back_vaps_buff_len];

    int temp_int;

    if ((temp_int = bpl::cfg_get_rdkb_extensions()) < 0) {
        LOG(ERROR) << "Failed reading 'rdkb_extensions'";
        return false;
    }
    db->device_conf.rdkb_extensions_enabled = static_cast<bool>(temp_int);

    if (!bpl::cfg_get_band_steering(db->device_conf.client_band_steering_enabled)) {
        LOG(DEBUG) << "Failed to read cfg_get_band_steering, setting to default value: "
                   << beerocks::bpl::DEFAULT_BAND_STEERING;

        db->device_conf.client_band_steering_enabled = beerocks::bpl::DEFAULT_BAND_STEERING;
    }

    if (!beerocks::bpl::cfg_get_client_roaming(
            db->device_conf.client_optimal_path_roaming_enabled)) {
        LOG(DEBUG) << "Failed to read cfg_get_client_roaming, setting to default value: "
                   << beerocks::bpl::DEFAULT_CLIENT_ROAMING;

        db->device_conf.client_optimal_path_roaming_enabled = beerocks::bpl::DEFAULT_CLIENT_ROAMING;
    }

    if ((temp_int = bpl::cfg_is_master()) < 0) {
        LOG(ERROR) << "Failed reading 'local_controller'";
        return false;
    }
    db->device_conf.local_controller = temp_int;
    if ((temp_int = bpl::cfg_get_management_mode()) < 0) {
        LOG(ERROR) << "Failed reading 'management_mode'";
        return false;
    }
    db->device_conf.management_mode = temp_int;
    if ((temp_int = bpl::cfg_get_operating_mode()) < 0) {
        LOG(ERROR) << "Failed reading 'operating_mode'";
        return false;
    }
    db->device_conf.operating_mode = uint8_t(temp_int);

    if ((temp_int = bpl::cfg_get_certification_mode()) < 0) {
        LOG(ERROR) << "Failed reading 'certification_mode'";
        return false;
    }
    db->device_conf.certification_mode = temp_int;

    if ((temp_int = bpl::cfg_get_stop_on_failure_attempts()) < 0) {
        LOG(ERROR) << "Failed reading 'stop_on_failure_attempts'";
        return false;
    }
    db->device_conf.stop_on_failure_attempts = temp_int;

    int backhaul_max_vaps;
    int backhaul_network_enabled;
    int backhaul_preferred_radio_band;
    if (bpl::cfg_get_backhaul_params(&backhaul_max_vaps, &backhaul_network_enabled,
                                     &backhaul_preferred_radio_band) < 0) {
        LOG(ERROR) << "Failed reading 'backhaul_max_vaps, backhaul_network_enabled, "
                      "backhaul_preferred_radio_band'!";
    }
    db->device_conf.back_radio.backhaul_max_vaps = static_cast<uint8_t>(backhaul_max_vaps);
    db->device_conf.back_radio.backhaul_network_enabled =
        static_cast<bool>(backhaul_network_enabled);
    db->device_conf.back_radio.backhaul_preferred_radio_band =
        bpl_band_to_freq_type(backhaul_preferred_radio_band);

    if (bpl::cfg_get_backhaul_vaps(back_vaps, back_vaps_buff_len) < 0) {
        LOG(ERROR) << "Failed reading beerocks backhaul_vaps parameters!";
        return false;
    }

    if (!bpl::cfg_get_zwdfs_enable(db->device_conf.zwdfs_enable)) {
        LOG(WARNING) << "cfg_get_zwdfs_enable() failed!, using default configuration, zwdfs is "
                     << (db->device_conf.zwdfs_enable ? std::string("enabled.")
                                                      : std::string("disabled."));
    }

    if (!bpl::cfg_get_best_channel_rank_threshold(db->device_conf.best_channel_rank_threshold)) {
        LOG(WARNING) << "cfg_get_best_channel_rank_threshold() failed!"
                     << " using default configuration ";
    }

    // Set local_gw flag
    db->device_conf.local_gw = (db->device_conf.operating_mode == BPL_OPER_MODE_GATEWAY ||
                                db->device_conf.operating_mode == BPL_OPER_MODE_GATEWAY_WISP);

    db->device_conf.client_optimal_path_roaming_prefer_signal_strength_enabled =
        0; // TODO add platform DB flag
    db->device_conf.client_11k_roaming_enabled =
        (db->device_conf.client_optimal_path_roaming_enabled ||
         db->device_conf.client_band_steering_enabled);

    db->device_conf.load_balancing_enabled   = 0; // for v1.3 TODO read from CAL DB
    db->device_conf.service_fairness_enabled = 0; // for v1.3 TODO read from CAL DB

    std::vector<std::string> lan_iface_list;
    if (beerocks::bpl::bpl_get_lan_interfaces(lan_iface_list)) {

        db->ethernet.lan.clear();

        std::string iface_mac;
        for (const auto &lan_iface : lan_iface_list) {

            if (beerocks::net::network_utils::linux_iface_get_mac(lan_iface, iface_mac)) {
                db->ethernet.lan.emplace_back(lan_iface, tlvf::mac_from_string(iface_mac));
            }
        }
    }

    LOG(DEBUG) << "iface " << iface_name << " settings:";
    LOG(DEBUG) << "client_band_steering_enabled: " << db->device_conf.client_band_steering_enabled;
    LOG(DEBUG) << "client_optimal_path_roaming_enabled: "
               << db->device_conf.client_optimal_path_roaming_enabled;
    LOG(DEBUG) << "client_optimal_path_roaming_prefer_signal_strength_enabled: "
               << db->device_conf.client_optimal_path_roaming_prefer_signal_strength_enabled;
    LOG(DEBUG) << "band_enabled: " << db->device_conf.front_radio.config[iface_name].band_enabled;
    LOG(DEBUG) << "local_gw: " << db->device_conf.local_gw;
    LOG(DEBUG) << "local_controller: " << db->device_conf.local_controller;
    LOG(DEBUG) << "backhaul_preferred_radio_band: "
               << db->device_conf.back_radio.backhaul_preferred_radio_band;
    LOG(DEBUG) << "rdkb_extensions: " << db->device_conf.rdkb_extensions_enabled;
    LOG(DEBUG) << "zwdfs_enable: " << db->device_conf.zwdfs_enable;
    LOG(DEBUG) << "best_channel_rank_threshold: " << db->device_conf.best_channel_rank_threshold;

    return true;
} // namespace beerocks

static std::string get_sta_iface(const std::string &hostap_iface)
{
    char sta_iface_str[BPL_IFNAME_LEN];
    if (bpl::cfg_get_sta_iface(hostap_iface.c_str(), sta_iface_str) < 0) {
        LOG(DEBUG) << "failed to read sta_iface for slave ";
        return std::string();
    }
    auto sta_iface = std::string(sta_iface_str);
    if (!beerocks::net::network_utils::linux_iface_exists(sta_iface)) {
        LOG(DEBUG) << "sta iface " << sta_iface << " does not exist, clearing it from config";
        return std::string();
    }
    return sta_iface;
}

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

std::string PlatformManager::query_db(const std::string &parameter)
{
    std::string ret;
    if (bpl::bpl_init() < 0) {
        ret = "Failed to initialize BPL!";
    } else {
        if (parameter == "is_master") {
            ret = (bpl::cfg_is_master() > 0 ? "true" : "false");
        } else if (parameter == "is_gateway") {
            auto operating_mode = bpl::cfg_get_operating_mode();
            ret                 = (operating_mode == BPL_OPER_MODE_GATEWAY ||
                           operating_mode == BPL_OPER_MODE_GATEWAY_WISP
                       ? "true"
                       : "false");
        } else if (parameter == "is_onboarding") {
            ret = (bpl::cfg_is_onboarding() > 0 ? "true" : "false");
        } else {
            ret = "Error, bad parameter.\n"
                  "Allowed parameters: \n"
                  " is_master \n"
                  " is_gateway \n"
                  " is_onboarding \n";
        }
    }
    return ret;
}

PlatformManager::PlatformManager(config_file::sConfigSlave &config_,
                                 const std::unordered_map<int, std::string> &interfaces_map_,
                                 logging &logger_,
                                 std::unique_ptr<beerocks::CmduServer> cmdu_server,
                                 std::shared_ptr<beerocks::TimerManager> timer_manager,
                                 std::shared_ptr<beerocks::EventLoop> event_loop)
    : m_cmdu_tx(m_tx_buffer, sizeof(m_tx_buffer)), config(config_), interfaces_map(interfaces_map_),
      logger(logger_), m_cmdu_server(std::move(cmdu_server)), m_timer_manager(timer_manager),
      m_event_loop(event_loop)
{
    LOG_IF(!m_cmdu_server, FATAL) << "CMDU server is a null pointer!";
    LOG_IF(!m_timer_manager, FATAL) << "Timer manager is a null pointer!";
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";

    enable_arp_monitor = (config.enable_arp_monitor == "1");

    int i = 0;
    for (int j = 0; j < IRE_MAX_SLAVES && i < BPL_NUM_OF_INTERFACES; ++j) {
        auto hostap_iface_elm = interfaces_map.find(j);
        if (hostap_iface_elm == interfaces_map.end() || hostap_iface_elm->second.empty())
            continue;

        auto hostap_iface = hostap_iface_elm->second;
        ap_ifaces.insert(hostap_iface);
        i++;
    }

    beerocks::CmduServer::EventHandlers handlers{
        .on_client_connected    = [&](int fd) { handle_connected(fd); },
        .on_client_disconnected = [&](int fd) { handle_disconnected(fd); },
        .on_cmdu_received       = [&](int fd, uint32_t iface_index, const sMacAddr &dst_mac,
                                const sMacAddr &src_mac,
                                ieee1905_1::CmduMessageRx &cmdu_rx) { handle_cmdu(fd, cmdu_rx); },
    };
    m_cmdu_server->set_handlers(handlers);
}

PlatformManager::~PlatformManager() { m_cmdu_server->clear_handlers(); }

bool PlatformManager::start()
{
    // In case of error in one of the steps of this method, we have to undo all the previous steps
    // (like when rolling back a database transaction, where either all steps get executed or none
    // of them gets executed)
    beerocks::Transaction transaction;

    // Create a timer to periodically check if WLAN parameters have changed
    m_check_wlan_params_changed_timer = m_timer_manager->add_timer(
        check_wlan_params_changed_timer_interval, check_wlan_params_changed_timer_interval,
        [&](int fd, beerocks::EventLoop &loop) {
            check_wlan_params_changed();
            return true;
        });
    if (m_check_wlan_params_changed_timer == beerocks::net::FileDescriptor::invalid_descriptor) {
        LOG(ERROR) << "Failed to create the check-WLAN-parameters-changed timer";
        return false;
    }
    LOG(DEBUG) << "Check-WLAN-parameters-changed timer created with fd = "
               << m_check_wlan_params_changed_timer;
    transaction.add_rollback_action(
        [&]() { m_timer_manager->remove_timer(m_check_wlan_params_changed_timer); });

    // Initialize the BPL (Beerocks Platform Library)
    if (bpl::bpl_init() < 0) {
        LOG(ERROR) << "Failed to initialize BPL!";
        return false;
    }
    transaction.add_rollback_action([&]() { bpl::bpl_close(); });

    int i = 0;
    for (int slave_num = 0; slave_num < IRE_MAX_SLAVES && i < BPL_NUM_OF_INTERFACES; ++slave_num) {

        auto hostap_iface_elm = interfaces_map.find(slave_num);
        if (hostap_iface_elm == interfaces_map.end() || hostap_iface_elm->second.empty())
            continue;

        config.sta_iface[slave_num] = get_sta_iface(hostap_iface_elm->second);

        if (config.sta_iface[slave_num].empty())
            continue;

        i++;
    }

    // Bridge & Backhaul interface
    is_onboarding_on_init = bpl::cfg_is_onboarding();
    if (is_onboarding_on_init) {
        LOG(DEBUG) << "Onboarding state.";
        for (int slave_num = 0; slave_num < IRE_MAX_SLAVES; slave_num++) {
            if (!config.sta_iface[slave_num].empty()) {
                load_iface_params(config.sta_iface[slave_num], beerocks::ARP_SRC_WIRELESS_BACK);
            }
        }
    } else {
        LOG(DEBUG) << "Non-onboarding state.";

        auto db = AgentDB::get();

        if (config.bridge_iface.empty()) {
            LOG(ERROR) << "bridge_iface is empty!";
            return false;
        }
        load_iface_params(config.bridge_iface, beerocks::ARP_SRC_ETH_FRONT);

        if (db->ethernet.wan.iface_name.empty()) {
            LOG(ERROR) << "wan.iface_name is empty!";
            return false;
        }
        load_iface_params(db->ethernet.wan.iface_name, beerocks::ARP_SRC_ETH_BACK);

        for (int slave_num = 0; slave_num < IRE_MAX_SLAVES; slave_num++) {
            if (!config.sta_iface[slave_num].empty()) {
                load_iface_params(config.sta_iface[slave_num], beerocks::ARP_SRC_WIRELESS_BACK);
            }
        }
    }

    // Start the async work queue
    m_should_stop = false;
    if (!work_queue.start()) {
        LOG(ERROR) << "Failed starting asynchronous work queue";
        return false;
    }

    transaction.commit();

    return true;
}

bool PlatformManager::stop()
{
    bool result = true;

    LOG(DEBUG) << "Stopping asynchronous work queue...";
    m_should_stop = true;
    work_queue.stop(true);

    // Stop the DHCP Monitor
    stop_dhcp_monitor();

    // Stop the ARP Monitor
    stop_arp_monitor();

    bpl::bpl_close();
    LOG(DEBUG) << "Closed BPL.";

    bpl_iface_wlan_params_map.clear();

    // Cancel and remove the check-WLAN-parameters-changed timer
    if (m_check_wlan_params_changed_timer != beerocks::net::FileDescriptor::invalid_descriptor) {
        if (!m_timer_manager->remove_timer(m_check_wlan_params_changed_timer)) {
            result = false;
        }
    }

    return result;
}

void PlatformManager::add_slave_socket(int fd, const std::string &iface_name)
{
    // Lock the slaves socket map
    std::unique_lock<std::mutex> lock(m_mtxSlaves);

    m_mapSlaves[fd] = iface_name;
}

void PlatformManager::del_slave_socket(int fd)
{
    // Lock the slaves socket map
    std::unique_lock<std::mutex> lock(m_mtxSlaves);

    // Remove the socket from the connections map
    m_mapSlaves.erase(fd);

    // Also check if that was the backhaul manager
    if (m_backhaul_manager_socket == fd) {
        m_backhaul_manager_socket = beerocks::net::FileDescriptor::invalid_descriptor;
    }
}

bool PlatformManager::send_cmdu_safe(int fd, ieee1905_1::CmduMessageTx &cmdu_tx)
{
    // Lock the slaves socket map
    std::unique_lock<std::mutex> lock(m_mtxSlaves);

    if (m_mapSlaves.find(fd) == m_mapSlaves.end()) {
        LOG(ERROR) << "Attempted send to invalid socket slave: " << fd;
        return false;
    }

    return send_cmdu(fd, cmdu_tx);
}

bool PlatformManager::send_cmdu(int fd, ieee1905_1::CmduMessageTx &cmdu_tx)
{
    return m_cmdu_server->send_cmdu(fd, cmdu_tx);
}

int PlatformManager::get_slave_socket_from_hostap_iface_name(const std::string &iface)
{
    auto it_slave = std::find_if(
        m_mapSlaves.begin(), m_mapSlaves.end(),
        [&iface](const std::pair<int, std::string> &slave) { return iface == slave.second; });

    if (it_slave != m_mapSlaves.end()) {
        return it_slave->first;
    }

    return beerocks::net::FileDescriptor::invalid_descriptor;
}

int PlatformManager::get_backhaul_socket()
{
    // Lock the slaves socket map
    std::unique_lock<std::mutex> lock(m_mtxSlaves);

    // If a slave containing the backhaul manager registered, return its socket.
    // If not, return the first socket from the connection map
    int fd = beerocks::net::FileDescriptor::invalid_descriptor;

    if (beerocks::net::FileDescriptor::invalid_descriptor != m_backhaul_manager_socket) {
        fd = m_backhaul_manager_socket;
    } else if (!m_mapSlaves.empty()) {
        fd = m_mapSlaves.begin()->first;
    }

    return fd;
}

void PlatformManager::load_iface_params(const std::string &strIface, beerocks::eArpSource eType)
{
    // Ignore empty interfaces
    if (strIface.empty()) {
        LOG(ERROR) << "strIface is empty!";
        return;
    }

    LOG(DEBUG) << "load_iface_params(), Interface " << strIface;

    m_mapIfaces[strIface] = {eType}; // Struct initialization
}

std::string PlatformManager::bridge_iface_from_mac(const sMacAddr &sMac)
{
    char iface_name[BPL_ARP_IFACE_NAME_LEN];

    // Read the interface name using BPL
    if (bpl::arp_get_bridge_iface(config.bridge_iface.c_str(), sMac.oct, iface_name) == -1) {
        return {};
    }

    return std::string(iface_name);
}

void PlatformManager::send_dhcp_notification(const std::string &op, const std::string &mac,
                                             const std::string &ip, const std::string &hostname)
{
    LOG(DEBUG) << "DHCP Event: " << op << ", mac: " << mac << ", ip: " << ip
               << ", hostname: " << hostname;
    auto dhcp_notif = message_com::create_vs_message<
        beerocks_message::cACTION_PLATFORM_DHCP_MONITOR_NOTIFICATION>(m_cmdu_tx);

    if (dhcp_notif == nullptr) {
        LOG(ERROR) << "Failed building ACTION_PLATFORM_DHCP_MONITOR_NOTIFICATION message!";
        return;
    }

    // Build the DHCP notification message
    if (op == "add")
        dhcp_notif->op() = beerocks_message::eDHCPOp_Add;
    else if (op == "del")
        dhcp_notif->op() = beerocks_message::eDHCPOp_Del;
    else if (op == "old")
        dhcp_notif->op() = beerocks_message::eDHCPOp_Old;

    dhcp_notif->mac()  = tlvf::mac_from_string(mac);
    dhcp_notif->ipv4() = beerocks::net::network_utils::ipv4_from_string(ip);
    string_utils::copy_string(dhcp_notif->hostname(0), hostname.c_str(), message::NODE_NAME_LENGTH);

    // Get a slave socket
    int fd = get_backhaul_socket();

    if (beerocks::net::FileDescriptor::invalid_descriptor != fd) {
        send_cmdu(fd, m_cmdu_tx);
    }
}

bool PlatformManager::check_wlan_params_changed()
{
    bool any_slave_changed = false;
    for (auto &elm : bpl_iface_wlan_params_map) {
        if (elm.second == nullptr) {
            LOG(ERROR) << "invalid map - pointer to NULL";
            return false;
        }
        bool wlan_params_changed = false;
        bpl::BPL_WLAN_PARAMS params;
        if (bpl::cfg_get_wifi_params(elm.first.c_str(), &params) < 0) {
            LOG(ERROR) << "Failed reading '" << elm.first << "' parameters!";
            return false;
        }

        if (elm.second->band_enabled != params.enabled) {
            elm.second->band_enabled = params.enabled;
            LOG(DEBUG) << "band_enabled changed";
            wlan_params_changed = true;
        }
        if (elm.second->channel != params.channel) {
            elm.second->channel = params.channel;
            LOG(DEBUG) << "channel changed";
            wlan_params_changed = true;
        }

        if (wlan_params_changed) {
            any_slave_changed = true;
            auto notification = message_com::create_vs_message<
                beerocks_message::cACTION_PLATFORM_WLAN_PARAMS_CHANGED_NOTIFICATION>(m_cmdu_tx);
            if (notification == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            notification->wlan_settings().band_enabled = elm.second->band_enabled;
            notification->wlan_settings().channel      = elm.second->channel;

            int fd = get_slave_socket_from_hostap_iface_name(elm.first);
            if (beerocks::net::FileDescriptor::invalid_descriptor == fd) {
                LOG(ERROR) << "failed to get slave socket from iface=" << elm.first;
                continue;
            }

            send_cmdu_safe(fd, m_cmdu_tx);
            LOG(DEBUG) << "wlan_params_changed - cmdu msg sent, iface=" << elm.first
                       << " cmdu msg sent, fd=" << fd;
        }
    }
    return any_slave_changed;
}

void PlatformManager::handle_connected(int fd) { LOG(INFO) << "UDS socket connected, fd = " << fd; }

void PlatformManager::handle_disconnected(int fd)
{
    auto it = m_mapSlaves.find(fd);
    if (it == m_mapSlaves.end()) {
        if (fd == m_backhaul_manager_socket) {
            LOG(INFO) << "Bachaul manager socket disconnected! fd = " << fd;
        } else {
            LOG(INFO) << "Non slave socket disconnected! fd = " << fd;
        }
        return;
    }

    std::string iface_name = m_mapSlaves[fd];
    LOG(DEBUG) << "Slave socket disconnected, iface = " << iface_name << ", fd = " << fd;

    // we should have only one per fd
    bpl_iface_wlan_params_map.erase(iface_name);

    del_slave_socket(fd);
}

bool PlatformManager::handle_cmdu(int fd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto beerocks_header = message_com::parse_intel_vs_message(cmdu_rx);
    if (!beerocks_header) {
        LOG(ERROR) << "Not a vendor specific message";
        return false;
    }

    if (beerocks_header->action() != beerocks_message::ACTION_PLATFORM) {
        LOG(ERROR) << "Unknown message, action: " << int(beerocks_header->action());
        return true;
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_PLATFORM_SON_SLAVE_REGISTER_REQUEST: {
        LOG(TRACE) << "ACTION_PLATFORM_SON_SLAVE_REGISTER_REQUEST";
        auto request =
            beerocks_header
                ->addClass<beerocks_message::cACTION_PLATFORM_SON_SLAVE_REGISTER_REQUEST>();
        if (request == nullptr) {
            LOG(ERROR) << "addClass cACTION_PLATFORM_SON_SLAVE_REGISTER_REQUEST failed";
            return false;
        }
        // Interface params
        std::string strIfaceName = std::string(request->iface_name(message::IFACE_NAME_LENGTH));
        LOG(DEBUG) << "Registering slave with interface = " << strIfaceName;

        add_slave_socket(fd, strIfaceName);

        work_queue.enqueue<void>([this, strIfaceName, fd]() {
            size_t tx_buffer_size = message_com::get_vs_cmdu_size_on_buffer<
                beerocks_message::cACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE>();
            uint8_t tx_buffer[tx_buffer_size];
            ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));

            //Response message (empty for now)
            auto register_response = message_com::create_vs_message<
                beerocks_message::cACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE>(cmdu_tx);

            if (register_response == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return;
            }

            uint8_t retry_cnt          = 0;
            register_response->valid() = 0;
            do {
                LOG(TRACE) << "Trying to read settings of iface:" << strIfaceName
                           << ", attempt=" << int(retry_cnt);
                if (fill_platform_settings(strIfaceName, bpl_iface_wlan_params_map)) {
                    register_response->valid() = 1;
                } else {
                    LOG(INFO) << "Reading settings of iface:" << strIfaceName
                              << ", attempt=" << int(retry_cnt) << " has failed!";

                    // reached max number of retries
                    if (++retry_cnt == PLATFORM_READ_CONF_MAX_ATTEMPTS)
                        break;

                    // sleep and retry
                    std::this_thread::sleep_for(std::chrono::seconds(PLATFORM_READ_CONF_RETRY_SEC));
                }
            } while (!register_response->valid() && !m_should_stop);

            if (register_response->valid()) {
                LOG(DEBUG) << "sending ACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE to "
                           << strIfaceName << " fd=" << fd;
                send_cmdu_safe(fd, cmdu_tx);
            }
        });

    } break;

    case beerocks_message::ACTION_PLATFORM_CHANGE_MODULE_LOGGING_LEVEL: {
        LOG(TRACE) << "ACTION_PLATFORM_CHANGE_MODULE_LOGGING_LEVEL";
        auto request =
            beerocks_header
                ->addClass<beerocks_message::cACTION_PLATFORM_CHANGE_MODULE_LOGGING_LEVEL>();
        if (request == nullptr) {
            LOG(ERROR) << "addClass ACTION_PLATFORM_CHANGE_MODULE_LOGGING_LEVEL failed";
            return false;
        }
        logger.set_log_level_state((beerocks::eLogLevel)request->params().log_level,
                                   request->params().enable);

    } break;

    case beerocks_message::ACTION_PLATFORM_ARP_QUERY_REQUEST: {
        LOG(TRACE) << "ACTION_PLATFORM_ARP_QUERY_REQUEST";

        auto request =
            beerocks_header->addClass<beerocks_message::cACTION_PLATFORM_ARP_QUERY_REQUEST>();
        if (request == nullptr) {
            LOG(ERROR) << "addClass cACTION_PLATFORM_ARP_QUERY_REQUEST failed";
            return false;
        }

        // Send a probe request to the ARP monitor
        if (!m_ctxArpMon) {
            LOG(WARNING) << "ARP monitor NOT active...";
            break;
        }

        if (bpl::arp_mon_probe(m_ctxArpMon, request->params().mac.oct, request->params().ipv4.oct,
                               beerocks_header->id()) != 0) {
            LOG(DEBUG) << "ARP probe failed!";
            break;
        }

        // Add the MAC to the arp entries map
        if (m_mapArpEntries.find(request->params().mac) == m_mapArpEntries.end()) {
            auto pArpEntry = std::make_shared<SArpEntry>();

            // Only the IP address is initialized at this point
            pArpEntry->ip =
                beerocks::net::network_utils::uint_ipv4_from_array(&request->params().ipv4.oct);
            pArpEntry->iface_index = -1;
            pArpEntry->last_seen   = std::chrono::steady_clock::now();

            LOG(DEBUG) << "Adding MAC " << request->params().mac << " to the ARP list...";

            m_mapArpEntries[request->params().mac] = pArpEntry;
        }

    } break;

    case beerocks_message::ACTION_PLATFORM_ADMIN_CREDENTIALS_GET_REQUEST: {
        // Request message
        LOG(TRACE) << "ACTION_PLATFORM_ADMIN_CREDENTIALS_GET_REQUEST";

        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_PLATFORM_ADMIN_CREDENTIALS_GET_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        memset(response->params().user_password, 0, message::USER_PASS_LEN);

        char pass[BPL_USER_PASS_LEN];

        if (bpl::cfg_get_administrator_credentials(pass) < 0) {
            LOG(ERROR) << "Failed reading administrator credentials!";
            response->result() = 0;
        } else {
            response->result() = 1;
        }

        string_utils::copy_string(response->params().user_password, pass, message::USER_PASS_LEN);

        // Sent with unsafe because BML is reachable only on platform thread
        send_cmdu(fd, m_cmdu_tx);

        //clear the pwd in the memory
        memset(&pass, 0, sizeof(pass));

        // deepcode ignore CopyPasteError: <memset might be optimized and compiler might not set it
        // 0 if its not used after memset>
        *(volatile char *)pass = *(volatile char *)pass;

    } break;
    case beerocks_message::ACTION_PLATFORM_GET_MASTER_SLAVE_VERSIONS_REQUEST: {
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_PLATFORM_GET_MASTER_SLAVE_VERSIONS_RESPONSE>(m_cmdu_tx);
        if (response == nullptr) {
            LOG(ERROR) << "addClass cACTION_PLATFORM_GET_MASTER_SLAVE_VERSIONS_RESPONSE failed";
            return false;
        }
        if (!master_version.empty() && !slave_version.empty()) {
            string_utils::copy_string(response->versions().master_version, master_version.c_str(),
                                      message::VERSION_LENGTH);
            string_utils::copy_string(response->versions().slave_version, slave_version.c_str(),
                                      message::VERSION_LENGTH);
            response->result() = 1;
        } else {
            response->result() = 0;
        }

        send_cmdu(fd, m_cmdu_tx);

    } break;
    case beerocks_message::ACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION: {
        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION>();
        if (notification == nullptr) {
            LOG(ERROR) << "addClass ACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION failed";
            return false;
        }
        master_version.assign(notification->versions().master_version);
        slave_version.assign(notification->versions().slave_version);
    } break;

    case beerocks_message::ACTION_PLATFORM_SON_SLAVE_BACKHAUL_CONNECTION_COMPLETE_NOTIFICATION: {
        LOG(DEBUG) << "ACTION_PLATFORM_SON_SLAVE_BACKHAUL_CONNECTION_COMPLETE_NOTIFICATION";
        auto notification = beerocks_header->addClass<
            beerocks_message::
                cACTION_PLATFORM_SON_SLAVE_BACKHAUL_CONNECTION_COMPLETE_NOTIFICATION>();
        if (notification == nullptr) {
            LOG(ERROR) << "addClass "
                          "cACTION_PLATFORM_SON_SLAVE_BACKHAUL_CONNECTION_COMPLETE_NOTIFICATION "
                          "failed";
            return false;
        }
        if (notification->is_backhaul_manager()) {
            LOG(DEBUG) << "slave is backhaul manager, updating";
            m_backhaul_manager_socket = fd;

            // Start ARP monitor
            if (enable_arp_monitor) {
                if (!init_arp_monitor()) {
                    LOG(ERROR) << "can't start ARP monitor";
                    return false;
                }
            }

            // Start DHCP monitor
            if (AgentDB::get()->device_conf.local_gw) {
                if (!init_dhcp_monitor()) {
                    LOG(ERROR) << "can't start DHCP monitor";
                    return false;
                }
            }
        }
    } break;

    case beerocks_message::ACTION_PLATFORM_ONBOARD_QUERY_REQUEST: {
        LOG(TRACE) << "ACTION_PLATFORM_ONBOARD_QUERY_REQUEST";
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_PLATFORM_ONBOARD_QUERY_RESPONSE>(m_cmdu_tx);
        if (response == nullptr) {
            LOG(ERROR) << "Failed building ONBOARD RESPONSE message!";
            return false;
        }
        response->params().onboarding = bpl::cfg_is_onboarding();

        // Sent with unsafe because BML is reachable only on platform thread
        send_cmdu(fd, m_cmdu_tx);

    } break;

    case beerocks_message::ACTION_PLATFORM_LOCAL_MASTER_GET_REQUEST: {
        LOG(TRACE) << "ACTION_PLATFORM_LOCAL_MASTER_GET_REQUEST";
        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_PLATFORM_LOCAL_MASTER_GET_RESPONSE>(m_cmdu_tx);
        if (response == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        // Read the value from CAL
        response->local_master() = bpl::cfg_is_master();

        // Sent with unsafe because BML is reachable only on platform thread
        send_cmdu(fd, m_cmdu_tx);

    } break;

    case beerocks_message::ACTION_PLATFORM_WIFI_CREDENTIALS_GET_REQUEST: {
        // Request message
        auto request =
            beerocks_header
                ->addClass<beerocks_message::cACTION_PLATFORM_WIFI_CREDENTIALS_GET_REQUEST>();
        if (request == nullptr) {
            LOG(ERROR) << "addClass cACTION_PLATFORM_WIFI_CREDENTIALS_GET_REQUEST failed";
            break;
        }

        //TODO use vap_id, for now assume vap_id == MAIN_VAP
        LOG(TRACE) << "ACTION_PLATFORM_WIFI_CREDENTIALS_GET_REQUEST, vap_id="
                   << int(request->vap_id());

        auto response = message_com::create_vs_message<
            beerocks_message::cACTION_PLATFORM_WIFI_CREDENTIALS_GET_RESPONSE>(m_cmdu_tx);

        if (response == nullptr) {
            LOG(ERROR) << "Failed building message!";
            break;
        }

        auto fill_credentials_msg = [](const int radio_dir, char *msg_ssid, char *msg_pass,
                                       uint8_t &msg_sec) -> bool {
            memset(msg_ssid, 0, message::WIFI_SSID_MAX_LENGTH);
            memset(msg_pass, 0, message::WIFI_PASS_MAX_LENGTH);

            char ssid[BPL_SSID_LEN];
            char pass[BPL_PASS_LEN];
            char sec[BPL_SEC_LEN];

            if (bpl::cfg_get_beerocks_credentials(radio_dir, ssid, pass, sec) < 0) {
                LOG(ERROR) << "Failed reading Wi-Fi credentials!";
                return false;
            } else {
                std::string sec_string(sec);
                if (sec_string == BPL_WLAN_SEC_NONE_STR) {
                    msg_sec = beerocks_message::eWiFiSec_None;
                } else if (sec_string == BPL_WLAN_SEC_WEP64_STR) {
                    msg_sec = beerocks_message::eWiFiSec_WEP64;
                } else if (sec_string == BPL_WLAN_SEC_WEP128_STR) {
                    msg_sec = beerocks_message::eWiFiSec_WEP128;
                } else if (sec_string == BPL_WLAN_SEC_WPA_PSK_STR) {
                    msg_sec = beerocks_message::eWiFiSec_WPA_PSK;
                } else if (sec_string == BPL_WLAN_SEC_WPA2_PSK_STR) {
                    msg_sec = beerocks_message::eWiFiSec_WPA2_PSK;
                } else if (sec_string == BPL_WLAN_SEC_WPA_WPA2_PSK_STR) {
                    msg_sec = beerocks_message::eWiFiSec_WPA_WPA2_PSK;
                } else {
                    msg_sec = beerocks_message::eWiFiSec_None;
                    LOG(WARNING) << "Unsupported Wi-Fi Security: " << sec_string;
                    return (false);
                }
            }

            string_utils::copy_string(msg_ssid, ssid, message::WIFI_SSID_MAX_LENGTH);
            string_utils::copy_string(msg_pass, pass, message::WIFI_PASS_MAX_LENGTH);

            //clear the pwd in the memory
            memset(&pass, 0, sizeof(pass));

            // deepcode ignore CopyPasteError: <memset might be optimized and compiler might not set
            // it 0 if its not used after memset>
            *(volatile char *)pass = *(volatile char *)pass;

            return true;
        };

        response->result() =
            fill_credentials_msg(BPL_RADIO_FRONT, response->front_params().ssid,
                                 response->front_params().pass, response->front_params().sec);
        response->result() =
            fill_credentials_msg(BPL_RADIO_BACK, response->front_params().ssid,
                                 response->front_params().pass, response->front_params().sec);

        LOG(INFO) << "fSSID: " << response->front_params().ssid
                  << " fPASS: " << response->front_params().pass
                  << " fSEC: " << response->front_params().sec;
        LOG(INFO) << "bSSID: " << response->front_params().ssid
                  << " bPASS: " << response->front_params().pass
                  << " bSEC: " << response->front_params().sec;

        // Sent with unsafe because BML is reachable only on platform thread
        send_cmdu(fd, m_cmdu_tx);

    } break;

    case beerocks_message::ACTION_PLATFORM_ONBOARD_SET_REQUEST: {
        LOG(TRACE) << "ACTION_PLATFORM_ONBOARD_SET_REQUEST";
        // Request message
        auto request =
            beerocks_header->addClass<beerocks_message::cACTION_PLATFORM_ONBOARD_SET_REQUEST>();
        if (request == nullptr) {
            LOG(ERROR) << "addClass cACTION_PLATFORM_ONBOARD_SET_REQUEST failed";
            break;
        }

        LOG(INFO) << "Set onboarding to " << std::to_string(request->params().onboarding);
        bpl::cfg_set_onboarding(int(request->params().onboarding));

        LOG(INFO) << "Success onboarding " << std::to_string(bpl::cfg_is_onboarding());
        // No response message is needed
    } break;

    case beerocks_message::ACTION_PLATFORM_WPS_ONBOARDING_REQUEST: {
        LOG(TRACE) << "ACTION_PLATFORM_WPS_ONBOARDING_REQUEST";

        auto request =
            beerocks_header->addClass<beerocks_message::cACTION_PLATFORM_WPS_ONBOARDING_REQUEST>();
        if (request == nullptr) {
            LOG(ERROR) << "addClass ACTION_PLATFORM_WPS_ONBOARDING_REQUEST failed";
            break;
        }

        std::string iface = request->iface_name(message::IFACE_NAME_LENGTH);

        work_queue.enqueue<void>(
            [this](std::string iface) {
                bpl::cfg_notify_onboarding_completed("SSID", "PASSWORD", "SECURITY", iface.c_str(),
                                                     0);
            },
            iface);
    } break;

    case beerocks_message::ACTION_PLATFORM_ERROR_NOTIFICATION: {
        auto error =
            beerocks_header->addClass<beerocks_message::cACTION_PLATFORM_ERROR_NOTIFICATION>();
        if (error == nullptr) {
            LOG(ERROR) << "addClass failed";
            break;
        }

        uint32_t error_code = error->code();
        std::string error_data(error->data(0));

        // Notify the SL asynchronously
        work_queue.enqueue<void>([error_code, error_data]() {
            LOG(DEBUG) << "PLATFORM ERROR NOTIFICATION - Code: " << error_code
                       << ", Data: " << error_data;

            bpl::cfg_notify_error(error_code, error_data.c_str());
        });

    } break;
    default: {
        LOG(ERROR) << "Unknown PLATFORM_MANAGER message, action_op: "
                   << int(beerocks_header->action_op());
        return (false);
    }
    }

    return true;
}

bool PlatformManager::handle_arp_monitor()
{
    auto arp_notif =
        message_com::create_vs_message<beerocks_message::cACTION_PLATFORM_ARP_MONITOR_NOTIFICATION>(
            m_cmdu_tx);
    if (arp_notif == nullptr) {
        LOG(ERROR) << "Failed building message!";
        return false;
    }

    // Process the message
    bpl::BPL_ARP_MON_ENTRY entry;
    if (bpl::arp_mon_process(m_ctxArpMon, &entry) != 0) {
        LOG(ERROR) << "Failed processing ARP monitor message!";
        return (false);
    }

    // Ignore IPs outside the monitored network, zeroed MACs or invalid state
    if (((beerocks::net::network_utils::uint_ipv4_from_array(entry.ip) & m_uiArpMonMask) !=
         (m_uiArpMonIP & m_uiArpMonMask)) ||
        (!memcmp(entry.mac, s_arrZeroMac, sizeof(entry.mac))) ||
        (!memcmp(entry.mac, s_arrBCastMac, sizeof(entry.mac))) ||
        (entry.state == beerocks::ARP_NUD_FAILED)) {

        // LOG(DEBUG) << "Ignoring ARP from: "
        //            << beerocks::net::network_utils::ipv4_to_string(entry.ip) << " ("
        //            << entry.mac << ")"
        //            << ", state: " << int(entry.state)
        //            << ", type: " << int(entry.type);

        return true;
    }

    // Copy entry values
    tlvf::mac_from_array(entry.mac, arp_notif->params().mac);
    std::copy_n(entry.ip, sizeof(beerocks::net::sIpv4Addr::oct), arp_notif->params().ipv4.oct);
    arp_notif->params().iface_idx = entry.iface_idx;
    arp_notif->params().state     = entry.state;
    arp_notif->params().source    = entry.source;
    arp_notif->params().type      = entry.type;

    // After processing the message, copy the ipv4 and mac as strings
    std::string client_ipv4 =
        beerocks::net::network_utils::ipv4_to_string(arp_notif->params().ipv4);
    std::string client_mac = tlvf::mac_to_string(arp_notif->params().mac);

    auto iIfaceIndex = arp_notif->params().iface_idx;

    auto iface_name = beerocks::net::network_utils::linux_get_iface_name(iIfaceIndex);

    if (iface_name.empty()) {
        LOG(ERROR) << "Failed to find iface of iface_index" << int(iIfaceIndex);
        return false;
    }

    int fd = get_slave_socket_from_hostap_iface_name(iface_name);

    // Use the Backhaul Manager Slave as the default destination
    if (beerocks::net::FileDescriptor::invalid_descriptor == fd) {
        fd = get_backhaul_socket();
        if (beerocks::net::FileDescriptor::invalid_descriptor == fd) {
            LOG(WARNING) << "Failed obtaining slave socket";
            return false;
        }
    }

    auto it_iface = m_mapIfaces.find(iface_name);
    if (it_iface != m_mapIfaces.end()) {
        auto &pIfaceParams         = it_iface->second;
        arp_notif->params().source = pIfaceParams.eType;

    } else if (entry.type != ARP_TYPE_DELNEIGH) {

        std::string mac  = tlvf::mac_to_string(arp_notif->params().mac);
        std::string ipv4 = beerocks::net::network_utils::ipv4_to_string(arp_notif->params().ipv4);
        LOG(WARNING) << "Interface index " << int(iIfaceIndex) << " not found! mac=" << mac
                     << ", ipv4=" << ipv4;
        return (false);
    }

    std::string source = ((arp_notif->params().source == beerocks::ARP_SRC_ETH_BACK) ||
                          (arp_notif->params().source == beerocks::ARP_SRC_WIRELESS_BACK))
                             ? "BACK"
                             : "FRONT";

    // Send the message to the Slave
    LOG(INFO) << "ARP - Interface: " << iface_name << ", State: " << int(arp_notif->params().state)
              << ", IP: " << client_ipv4 << " (" << client_mac << ")"
              << ", Source: " << source << ", Type: " << int(arp_notif->params().type);

    // Check if the master should be notified
    bool fSendNotif = true;
    if (entry.type != ARP_TYPE_DELNEIGH) {
        auto pArpEntry = m_mapArpEntries.find(arp_notif->params().mac);

        if (pArpEntry != m_mapArpEntries.end()) {

            auto now                = std::chrono::steady_clock::now();
            auto last_seen_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          now - pArpEntry->second->last_seen)
                                          .count();

            // Check for IP/Inteface changes
            if ((pArpEntry->second->ip != beerocks::net::network_utils::uint_ipv4_from_array(
                                              arp_notif->params().ipv4.oct)) ||
                (pArpEntry->second->iface_index != int(arp_notif->params().iface_idx)) ||
                (last_seen_duration >= ARP_NOTIF_INTERVAL)) {

                // Update the entry
                pArpEntry->second->ip = beerocks::net::network_utils::uint_ipv4_from_array(
                    arp_notif->params().ipv4.oct);
                pArpEntry->second->iface_index = arp_notif->params().iface_idx;
                pArpEntry->second->last_seen   = now;

                LOG(DEBUG) << "Client last seen " << last_seen_duration
                           << " milliseconds ago. Sending notification!";

            } else {
                // Do NOT send notification
                fSendNotif = false;

                LOG(DEBUG) << "Client last seen " << last_seen_duration
                           << " milliseconds ago. Skipping notification...";
            }
        }
    }

    // Send the message to the slave
    if ((beerocks::net::FileDescriptor::invalid_descriptor != fd) && fSendNotif) {
        send_cmdu_safe(fd, m_cmdu_tx);
    }

    return (true);
}

bool PlatformManager::handle_arp_raw()
{
    // Skip invalid ARP packets
    bpl::BPL_ARP_MON_ENTRY entry;
    int task_id = bpl::arp_mon_process_raw_arp(m_ctxArpMon, &entry);
    if (task_id == 0) {
        // task-id equals to 0  means nodes list is empty
        // not an error, but no further work is required
        return true;
    } else if (task_id < 0) {
        return false;
    }

    auto arp_resp =
        message_com::create_vs_message<beerocks_message::cACTION_PLATFORM_ARP_QUERY_RESPONSE>(
            m_cmdu_tx, task_id);

    if (arp_resp == nullptr) {
        LOG(ERROR) << "Failed building cACTION_PLATFORM_ARP_QUERY_RESPONSE message!";
        return false;
    }

    // Copy entry values
    tlvf::mac_from_array(entry.mac, arp_resp->params().mac);
    std::copy_n(entry.ip, sizeof(arp_resp->params().ipv4.oct), arp_resp->params().ipv4.oct);
    arp_resp->params().iface_idx = entry.iface_idx;
    arp_resp->params().state     = entry.state;
    arp_resp->params().source    = entry.source;

    std::string strIface = bridge_iface_from_mac(arp_resp->params().mac);

    if (strIface.empty())
        return (false);

    // Find the interface index and source
    SIfaceParams *pIfaceParams = nullptr;
    auto it                    = m_mapIfaces.find(strIface);
    if (it != m_mapIfaces.end()) {
        pIfaceParams = &it->second;
    }

    int iIfaceIndex = if_nametoindex(strIface.c_str());

    if (iIfaceIndex == 0) {
        LOG(WARNING) << "Failed reading interface index for (" << strIface
                     << "): " << strerror(errno);

        return false;
    }

    // Update ARP response parameters
    arp_resp->params().iface_idx = (pIfaceParams) ? iIfaceIndex : 0;
    arp_resp->params().source =
        (pIfaceParams) ? uint8_t(pIfaceParams->eType) : uint8_t(beerocks::ARP_SRC_ETH_FRONT);

    std::string strSource =
        (pIfaceParams && ((pIfaceParams->eType == beerocks::ARP_SRC_ETH_BACK) ||
                          (pIfaceParams->eType == beerocks::ARP_SRC_WIRELESS_BACK)))
            ? "BACK"
            : "FRONT";

    LOG(DEBUG) << "Discovered IP: "
               << beerocks::net::network_utils::ipv4_to_string(arp_resp->params().ipv4) << " ("
               << arp_resp->params().mac << ") on '" << strIface << "' (" << strSource << ")";

    // Update ARP entry parameters
    auto pArpEntry = m_mapArpEntries.find(arp_resp->params().mac);

    if (pArpEntry != m_mapArpEntries.end()) {
        pArpEntry->second->ip =
            beerocks::net::network_utils::uint_ipv4_from_array(arp_resp->params().ipv4.oct);
        pArpEntry->second->iface_index = arp_resp->params().iface_idx;
        pArpEntry->second->last_seen   = std::chrono::steady_clock::now();
    } else {
        // This should not happen since the client is added to the list on query request...
        LOG(WARNING) << "MAC " << arp_resp->params().mac
                     << " was NOT found in the ARP entries list...";
    }

    // Get a slave socket
    int fd = get_backhaul_socket();

    if (beerocks::net::FileDescriptor::invalid_descriptor != fd) {
        LOG(TRACE) << "ACTION_PLATFORM_ARP_QUERY_RESPONSE mac=" << arp_resp->params().mac
                   << " task_id=" << task_id;
        send_cmdu_safe(fd, m_cmdu_tx);
    }

    return (true);
}

void PlatformManager::clean_old_arp_entries()
{
    auto now = std::chrono::steady_clock::now();

    for (auto it = m_mapArpEntries.begin(); it != m_mapArpEntries.end();) {

        auto last_seen_duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->last_seen)
                .count();

        // If the client wasn't seen --> erase it
        if (last_seen_duration >= ARP_NOTIF_INTERVAL) {
            LOG(INFO) << "Removing client with MAC " << it->first
                      << " due to inactivity for more than " << last_seen_duration
                      << " milliseconds.";

            it = m_mapArpEntries.erase(it);
        } else {
            it++;
        }
    }
}

bool PlatformManager::init_arp_monitor()
{
    if (!m_ctxArpMon) {
        LOG(DEBUG) << "Starting ARP Monitor...";

        // Read IP/Netmask of the monitored interface
        beerocks::net::network_utils::raw_iface_info info;
        if (!beerocks::net::network_utils::get_raw_iface_info(config.bridge_iface, info)) {
            LOG(ERROR) << "Failed reading '" + config.bridge_iface + "' information";
            return false;
        }

        int ret = bpl::arp_mon_start(&m_ctxArpMon, config.bridge_iface.c_str());
        if (ret < 0) {
            // If arp_monitor failed to start, continue without it. It might failed due to
            // insufficient permissions. Detailed error message is printed inside.
            if (ret == -int(bpl::eErrorCode::OPERATION_NOT_SUPPORTED)) {
                LOG(INFO) << "Skip starting ARP monitor (not supported)";
                return (true);
            }
            LOG(ERROR) << "Failed starting ARP monitor!";
            return (false);
        }

        m_uiArpMonIP   = info.ipa.s_addr;
        m_uiArpMonMask = info.nmask.s_addr;

        // TODO: PPM-639 Inject ARP monitor to platform manager
        if (!m_arp_raw_socket_connection) {
            m_arp_raw_socket_connection = std::make_unique<beerocks::net::SocketConnectionImpl>(
                std::make_shared<beerocks::net::ConnectedSocket>(
                    bpl::arp_mon_get_raw_arp_fd(m_ctxArpMon)));
            if (!m_arp_raw_socket_connection) {
                LOG(ERROR) << "Unable to create ARP raw connection!";
                stop_arp_monitor();
                return false;
            }

            beerocks::EventLoop::EventHandlers handlers;
            // Handle event
            handlers.on_read = [&](int fd, EventLoop &loop) {
                if (!handle_arp_raw()) {
                    LOG(ERROR) << "handle_arp_raw failed, restarting ARP monitor";
                    if (!restart_arp_monitor()) {
                        LOG(ERROR) << "failed to restart ARP monitor";
                    }
                }
                return true;
            };

            // Remove the socket on disconnection or error
            handlers.on_disconnect = [&](int fd, EventLoop &loop) {
                m_arp_raw_socket_connection.reset();
                stop_arp_monitor();
                return true;
            };
            handlers.on_error = handlers.on_disconnect;

            if (!m_event_loop->register_handlers(m_arp_raw_socket_connection->socket()->fd(),
                                                 handlers)) {
                LOG(ERROR) << "Unable to register handlers for ARP raw connection!";
                stop_arp_monitor();
                return false;
            }
        }

        if (!m_arp_mon_socket_connection) {
            m_arp_mon_socket_connection = std::make_unique<beerocks::net::SocketConnectionImpl>(
                std::make_shared<beerocks::net::ConnectedSocket>(bpl::arp_mon_get_fd(m_ctxArpMon)));
            if (!m_arp_mon_socket_connection) {
                LOG(ERROR) << "Unable to create ARP monitor connection!";
                stop_arp_monitor();
                return false;
            }

            beerocks::EventLoop::EventHandlers handlers;
            // Handle event
            handlers.on_read = [&](int fd, EventLoop &loop) {
                if (!handle_arp_monitor()) {
                    LOG(ERROR) << "handle_arp_monitor failed, restarting ARP monitor";
                    if (!restart_arp_monitor()) {
                        LOG(ERROR) << "failed to restart ARP monitor";
                    }
                }
                return true;
            };

            // Remove the socket on disconnection or error
            handlers.on_disconnect = [&](int fd, EventLoop &loop) {
                m_arp_mon_socket_connection.reset();
                stop_arp_monitor();
                return true;
            };
            handlers.on_error = handlers.on_disconnect;

            if (!m_event_loop->register_handlers(m_arp_mon_socket_connection->socket()->fd(),
                                                 handlers)) {
                LOG(ERROR) << "Unable to register handlers for ARP monitor connection!";
                stop_arp_monitor();
                return false;
            }
        }

        LOG(DEBUG) << "ARP Monitor started on interface '" << config.bridge_iface << "' ("
                   << beerocks::net::network_utils::ipv4_to_string(m_uiArpMonIP) << "/"
                   << beerocks::net::network_utils::ipv4_to_string(m_uiArpMonMask) << ")";

        // Initialize the ARP entries cleanup timestamp
        m_tpArpEntriesCleanup = std::chrono::steady_clock::now();

        // Create a timer to periodically clean old ARP table entries
        m_clean_old_arp_entries_timer = m_timer_manager->add_timer(
            clean_old_arp_entries_timer_interval, clean_old_arp_entries_timer_interval,
            [&](int fd, beerocks::EventLoop &loop) {
                clean_old_arp_entries();
                return true;
            });
        if (m_clean_old_arp_entries_timer == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(ERROR) << "Failed to create the clean-old-ARP-entries timer";
            stop_arp_monitor();
            return false;
        }
    }

    return true;
}

void PlatformManager::stop_arp_monitor()
{
    if (m_ctxArpMon) {
        bpl::arp_mon_stop(m_ctxArpMon);
        LOG(DEBUG) << "ARP Monitor Stopped.";
        m_ctxArpMon = nullptr;
    }

    if (m_arp_raw_socket_connection) {
        // Remove installed event handlers for the connected socket
        m_event_loop->remove_handlers(m_arp_raw_socket_connection->socket()->fd());

        m_arp_raw_socket_connection.reset();
    }

    if (m_arp_mon_socket_connection) {
        // Remove installed event handlers for the connected socket
        m_event_loop->remove_handlers(m_arp_mon_socket_connection->socket()->fd());

        m_arp_mon_socket_connection.reset();
    }

    // Cancel and remove the clean-old-ARP-entries timer
    if (m_clean_old_arp_entries_timer != beerocks::net::FileDescriptor::invalid_descriptor) {
        m_timer_manager->remove_timer(m_clean_old_arp_entries_timer);
    }
}

bool PlatformManager::restart_arp_monitor()
{
    stop_arp_monitor();

    if (!init_arp_monitor()) {
        LOG(ERROR) << "can't start ARP monitor";
        return false;
    }

    return true;
}

bool PlatformManager::init_dhcp_monitor()
{
    static auto dhcp_monitor_cb_wrapper = [&](const std::string &op, const std::string &mac,
                                              const std::string &ip, const std::string &hostname) {
        send_dhcp_notification(op, mac, ip, hostname);
    };

    // TODO: PPM-639 Inject DHCP monitor to platform manager
    if (!m_dhcp_mon_socket_connection) {
        int dhcp_mon_fd = bpl::dhcp_mon_start(
            [](const char *op, const char *mac, const char *ip, const char *hostname) {
                dhcp_monitor_cb_wrapper(op, mac, ip, hostname);
            });
        if (dhcp_mon_fd < 0) {
            if (dhcp_mon_fd == -int(bpl::eErrorCode::OPERATION_NOT_SUPPORTED)) {
                LOG(INFO) << "Skip starting DHCP monitor (not supported)";
                return (true);
            }
            LOG(ERROR) << "Failed starting DHCP monitor: " << dhcp_mon_fd;
            return (false);
        }

        m_dhcp_mon_socket_connection = std::make_unique<beerocks::net::SocketConnectionImpl>(
            std::make_shared<beerocks::net::ConnectedSocket>(dhcp_mon_fd));
        if (!m_dhcp_mon_socket_connection) {
            LOG(ERROR) << "Unable to create DHCP monitor connection!";
            stop_dhcp_monitor();
            return false;
        }

        beerocks::EventLoop::EventHandlers handlers;
        // Handle event
        handlers.on_read = [&](int fd, EventLoop &loop) {
            bpl::dhcp_mon_handle_event();
            return true;
        };

        handlers.on_disconnect = [&](int fd, EventLoop &loop) {
            m_dhcp_mon_socket_connection.reset();
            stop_dhcp_monitor();
            return true;
        };
        handlers.on_error = handlers.on_disconnect;

        if (!m_event_loop->register_handlers(m_dhcp_mon_socket_connection->socket()->fd(),
                                             handlers)) {
            LOG(ERROR) << "Unable to register handlers for DHCP monitor connection !";
            stop_dhcp_monitor();
            return false;
        }

        LOG(DEBUG) << "DHCP Monitor started, fd = " << dhcp_mon_fd;
    }

    return true;
}

void PlatformManager::stop_dhcp_monitor()
{
    if (bpl::dhcp_mon_stop() != 0) {
        LOG(ERROR) << "Failed stopping DHCP Monitor!";
    } else {
        LOG(DEBUG) << "DHCP Monitor Stopped.";
    }

    if (m_dhcp_mon_socket_connection) {
        // Remove installed event handlers for the connected socket
        m_event_loop->remove_handlers(m_dhcp_mon_socket_connection->socket()->fd());

        m_dhcp_mon_socket_connection.reset();
    }
}

} // namespace beerocks
