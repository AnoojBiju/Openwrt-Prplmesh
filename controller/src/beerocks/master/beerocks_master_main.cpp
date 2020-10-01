/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_cmdu_server_impl.h>
#include <bcl/beerocks_config_file.h>
#include <bcl/beerocks_event_loop_impl.h>
#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_ucc_parser_message_impl.h>
#include <bcl/beerocks_ucc_serializer_message_impl.h>
#include <bcl/beerocks_ucc_server_impl.h>
#include <bcl/beerocks_version.h>
#include <bcl/network/cmdu_parser_stream_impl.h>
#include <bcl/network/cmdu_serializer_stream_impl.h>
#include <bcl/network/network_utils.h>
#include <bcl/network/sockets_impl.h>
#include <bpl/bpl_cfg.h>
#include <mapf/common/utils.h>

#include <easylogging++.h>

#include "db/db.h"
#include "son_master_thread.h"

// #include <string>

// Do not use this macro anywhere else in ire process
// It should only be there in one place in each executable module
BEEROCKS_INIT_BEEROCKS_VERSION

static bool g_running     = true;
static bool s_kill_master = false;
static int s_signal       = 0;

// Pointer to logger instance
static beerocks::logging *s_pLogger = nullptr;

static void handle_signal()
{
    if (!s_signal)
        return;

    switch (s_signal) {

    // Terminate
    case SIGTERM:
    case SIGINT:
        LOG(INFO) << "Caught signal '" << strsignal(s_signal) << "' Exiting...";
        g_running = false;
        break;

    // Roll log file
    case SIGUSR1: {
        LOG(INFO) << "LOG Roll Signal!";
        if (!s_pLogger) {
            LOG(ERROR) << "Invalid logger pointer!";
            return;
        }

        s_pLogger->apply_settings();
        LOG(INFO) << "--- Start of file after roll ---";
        break;
    }

    default:
        LOG(WARNING) << "Unhandled Signal: '" << strsignal(s_signal) << "' Ignoring...";
        break;
    }

    s_signal = 0;
}

static void init_signals()
{
    // Signal handler function
    auto signal_handler = [](int signum) { s_signal = signum; };

    struct sigaction sigterm_action;
    sigterm_action.sa_handler = signal_handler;
    sigemptyset(&sigterm_action.sa_mask);
    sigterm_action.sa_flags = 0;
    sigaction(SIGTERM, &sigterm_action, NULL);

    struct sigaction sigint_action;
    sigint_action.sa_handler = signal_handler;
    sigemptyset(&sigint_action.sa_mask);
    sigint_action.sa_flags = 0;
    sigaction(SIGINT, &sigint_action, NULL);

    struct sigaction sigusr1_action;
    sigusr1_action.sa_handler = signal_handler;
    sigemptyset(&sigusr1_action.sa_mask);
    sigusr1_action.sa_flags = 0;
    sigaction(SIGUSR1, &sigusr1_action, NULL);
}

static bool parse_arguments(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "k")) != -1) {
        switch (opt) {
        case 'k': {
            s_kill_master = true;
            break;
        }
        case '?': {
            if (isprint(optopt)) {
                LOG(ERROR) << "Unknown option -" << optopt << "!";
                return false;
            } else {
                LOG(ERROR) << "Unknown character " << optopt << "!";
                return false;
            }
            break;
        }
        }
    }
    return true;
}

static void fill_master_config(son::db::sDbMasterConfig &master_conf,
                               beerocks::config_file::sConfigMaster &main_master_conf)
{
    master_conf.vendor = main_master_conf.vendor;
    master_conf.model  = main_master_conf.model;
    master_conf.ucc_listener_port =
        beerocks::string_utils::stoi(main_master_conf.ucc_listener_port);
    master_conf.load_ire_roaming          = (main_master_conf.load_ire_roaming == "1");
    master_conf.load_service_fairness     = (main_master_conf.load_service_fairness == "1");
    master_conf.load_dfs_reentry          = (main_master_conf.load_dfs_reentry == "1");
    master_conf.load_rdkb_extensions      = (main_master_conf.load_rdkb_extensions == "1");
    master_conf.load_client_band_steering = (main_master_conf.load_client_band_steering == "1");
    master_conf.load_client_optimal_path_roaming =
        (main_master_conf.load_client_optimal_path_roaming == "1");
    master_conf.load_client_11k_roaming    = (main_master_conf.load_client_11k_roaming == "1");
    master_conf.load_legacy_client_roaming = (main_master_conf.load_legacy_client_roaming == "1");
    master_conf.load_load_balancing        = (main_master_conf.load_load_balancing == "1");
    master_conf.load_diagnostics_measurements =
        (main_master_conf.load_diagnostics_measurements == "1");
    master_conf.load_backhaul_measurements = (main_master_conf.load_backhaul_measurements == "1");
    master_conf.load_front_measurements    = (main_master_conf.load_front_measurements == "1");
    master_conf.load_health_check          = (main_master_conf.load_health_check == "1");
    master_conf.load_monitor_on_vaps       = (main_master_conf.load_monitor_on_vaps == "1");
    master_conf.diagnostics_measurements_polling_rate_sec =
        beerocks::string_utils::stoi(main_master_conf.diagnostics_measurements_polling_rate_sec);
    master_conf.ire_rssi_report_rate_sec =
        beerocks::string_utils::stoi(main_master_conf.ire_rssi_report_rate_sec);
    master_conf.roaming_hysteresis_percent_bonus =
        beerocks::string_utils::stoi(main_master_conf.roaming_hysteresis_percent_bonus);
    master_conf.roaming_unconnected_client_rssi_compensation_db = beerocks::string_utils::stoi(
        main_master_conf.roaming_unconnected_client_rssi_compensation_db);
    master_conf.roaming_hop_percent_penalty =
        beerocks::string_utils::stoi(main_master_conf.roaming_hop_percent_penalty);
    master_conf.roaming_band_pathloss_delta_db =
        beerocks::string_utils::stoi(main_master_conf.roaming_band_pathloss_delta_db);
    master_conf.roaming_5ghz_failed_attemps_threshold =
        beerocks::string_utils::stoi(main_master_conf.roaming_5ghz_failed_attemps_threshold);
    master_conf.roaming_24ghz_failed_attemps_threshold =
        beerocks::string_utils::stoi(main_master_conf.roaming_24ghz_failed_attemps_threshold);
    master_conf.roaming_11v_failed_attemps_threshold =
        beerocks::string_utils::stoi(main_master_conf.roaming_11v_failed_attemps_threshold);
    master_conf.roaming_rssi_cutoff_db =
        beerocks::string_utils::stoi(main_master_conf.roaming_rssi_cutoff_db);
    master_conf.monitor_total_ch_load_notification_lo_th_percent = beerocks::string_utils::stoi(
        main_master_conf.monitor_total_channel_load_notification_lo_th_percent);
    master_conf.monitor_total_ch_load_notification_hi_th_percent = beerocks::string_utils::stoi(
        main_master_conf.monitor_total_channel_load_notification_hi_th_percent);
    master_conf.monitor_total_ch_load_notification_delta_th_percent = beerocks::string_utils::stoi(
        main_master_conf.monitor_total_channel_load_notification_delta_th_percent);
    master_conf.monitor_min_active_clients =
        beerocks::string_utils::stoi(main_master_conf.monitor_min_active_clients);
    master_conf.monitor_active_client_th =
        beerocks::string_utils::stoi(main_master_conf.monitor_active_client_th);
    master_conf.monitor_client_load_notification_delta_th_percent = beerocks::string_utils::stoi(
        main_master_conf.monitor_client_load_notification_delta_th_percent);
    master_conf.monitor_ap_idle_threshold_B =
        beerocks::string_utils::stoi(main_master_conf.monitor_ap_idle_threshold_B);
    master_conf.monitor_ap_active_threshold_B =
        beerocks::string_utils::stoi(main_master_conf.monitor_ap_active_threshold_B);
    master_conf.monitor_ap_idle_stable_time_sec =
        beerocks::string_utils::stoi(main_master_conf.monitor_ap_idle_stable_time_sec);
    master_conf.monitor_rx_rssi_notification_threshold_dbm =
        beerocks::string_utils::stoi(main_master_conf.monitor_rx_rssi_notification_threshold_dbm);
    master_conf.monitor_rx_rssi_notification_delta_db =
        beerocks::string_utils::stoi(main_master_conf.monitor_rx_rssi_notification_delta_db);
    master_conf.monitor_disable_initiative_arp =
        beerocks::string_utils::stoi(main_master_conf.monitor_disable_initiative_arp);
    master_conf.channel_selection_random_delay =
        beerocks::string_utils::stoi(main_master_conf.channel_selection_random_delay);
    master_conf.fail_safe_5G_frequency =
        beerocks::string_utils::stoi(main_master_conf.fail_safe_5G_frequency);
    master_conf.fail_safe_5G_bw = beerocks::string_utils::stoi(main_master_conf.fail_safe_5G_bw);
    master_conf.fail_safe_5G_vht_frequency =
        beerocks::string_utils::stoi(main_master_conf.fail_safe_5G_vht_frequency);
    master_conf.channel_selection_long_delay =
        beerocks::string_utils::stoi(main_master_conf.channel_selection_long_delay);
    master_conf.roaming_sticky_client_rssi_threshold =
        beerocks::string_utils::stoi(main_master_conf.roaming_sticky_client_rssi_threshold);
    master_conf.credentials_change_timeout_sec =
        beerocks::string_utils::stoi(main_master_conf.credentials_change_timeout_sec);
    // get channel vector
    std::string s         = main_master_conf.global_restricted_channels;
    std::string delimiter = ",";

    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        master_conf.global_restricted_channels.push_back(beerocks::string_utils::stoi(token));
        s.erase(0, pos + delimiter.length());
    }
    if (!s.empty()) {
        master_conf.global_restricted_channels.push_back(beerocks::string_utils::stoi(s));
    }

    // platform settings
    master_conf.certification_mode = beerocks::bpl::cfg_get_certification_mode();
    char load_steer_on_vaps[BPL_LOAD_STEER_ON_VAPS_LEN] = {0};
    if (beerocks::bpl::cfg_get_load_steer_on_vaps(beerocks::IRE_MAX_SLAVES, load_steer_on_vaps) <
        0) {
        master_conf.load_steer_on_vaps = std::string();
    } else {
        master_conf.load_steer_on_vaps = std::string(load_steer_on_vaps);
    }

    if (!beerocks::bpl::cfg_get_persistent_db_enable(master_conf.persistent_db)) {
        LOG(DEBUG) << "failed to read persistent db enable, setting to default value: "
                   << bool(beerocks::bpl::DEFAULT_PERSISTENT_DB);
        master_conf.persistent_db = bool(beerocks::bpl::DEFAULT_PERSISTENT_DB);
    }
    if (!beerocks::bpl::cfg_get_clients_persistent_db_max_size(
            master_conf.clients_persistent_db_max_size)) {
        LOG(DEBUG)
            << "failed to read max number of clients in persistent db, setting to default value: "
            << beerocks::bpl::DEFAULT_CLIENTS_PERSISTENT_DB_MAX_SIZE;
        master_conf.clients_persistent_db_max_size =
            beerocks::bpl::DEFAULT_CLIENTS_PERSISTENT_DB_MAX_SIZE;
    }
    if (!beerocks::bpl::cfg_get_max_timelife_delay_days(master_conf.max_timelife_delay_days)) {
        LOG(DEBUG)
            << "failed to read max lifetime of clients in persistent db, setting to default value: "
            << beerocks::bpl::DEFAULT_MAX_TIMELIFE_DELAY_DAYS << " days";
        master_conf.max_timelife_delay_days = beerocks::bpl::DEFAULT_MAX_TIMELIFE_DELAY_DAYS;
    }
    if (!beerocks::bpl::cfg_get_unfriendly_device_max_timelife_delay_days(
            master_conf.unfriendly_device_max_timelife_delay_days)) {
        LOG(DEBUG) << "failed to read max lifetime of unfriendly clients in persistent db, setting "
                      "to default value: "
                   << beerocks::bpl::DEFAULT_UNFRIENDLY_DEVICE_MAX_TIMELIFE_DELAY_DAYS << " days";
        master_conf.unfriendly_device_max_timelife_delay_days =
            beerocks::bpl::DEFAULT_UNFRIENDLY_DEVICE_MAX_TIMELIFE_DELAY_DAYS;
    }
}

static std::shared_ptr<beerocks::net::UdsAddress> create_uds_address(const std::string &path)
{
    // When no longer required, the UDS socket pathname should be deleted using unlink or remove.
    auto deleter = [path](beerocks::net::UdsAddress *p) {
        if (p) {
            delete p;
        }
        unlink(path.c_str());
    };

    // Remove given path in case it exists
    unlink(path.c_str());

    // Create UDS address from given path (using custom deleter)
    return std::shared_ptr<beerocks::net::UdsAddress>(new beerocks::net::UdsAddress(path), deleter);
}

static std::unique_ptr<beerocks::net::ServerSocket>
create_server_socket(const beerocks::net::UdsAddress &address)
{
    // Create UDS socket
    auto socket = std::make_shared<beerocks::net::UdsSocket>();

    // Create UDS server socket to listen for and accept incoming connections from clients that
    // will send CMDU messages through that connections.
    using UdsServerSocket = beerocks::net::ServerSocketImpl<beerocks::net::UdsSocket>;
    auto server_socket    = std::make_unique<UdsServerSocket>(socket);
    if (!server_socket) {
        LOG(ERROR) << "Unable to create server socket";
        return nullptr;
    }

    // TODO: this code will be commented out until this server socket finally replaces current
    // server socket in the son_master_thread
    /*
    // Bind server socket to that UDS address
    if (!server_socket->bind(address)) {
        LOG(ERROR) << "Unable to bind server socket to UDS address: '" << address.path() << "'";
        return nullptr;
    }

    // Listen for incoming connection requests
    if (!server_socket->listen()) {
        LOG(ERROR) << "Unable to listen for connection requests at UDS address: '" << address.path()
                   << "'";
        return nullptr;
    }
    */

    return server_socket;
}

static std::unique_ptr<beerocks::net::ServerSocket> create_ucc_server_socket(uint16_t port)
{
    // Create TCP socket
    auto socket = std::make_shared<beerocks::net::TcpSocket>();

    // Create TCP server socket to listen for and accept incoming connections from clients that
    // will send UCC commands through that connections.
    using TcpServerSocket = beerocks::net::ServerSocketImpl<beerocks::net::TcpSocket>;
    auto server_socket    = std::make_unique<TcpServerSocket>(socket);

    // Internet address to bind the socket to
    beerocks::net::InternetAddress address(port);

    // TODO: this code will be commented out until this server socket finally replaces current
    // server socket in the beerocks_ucc_listener
    /*
    // Bind server socket to that TCP address
    if (!server_socket->bind(address)) {
        LOG(ERROR) << "Unable to bind server socket to TCP address at port: " << port;
        return nullptr;
    }

    // Listen for incoming connection requests
    if (!server_socket->listen()) {
        LOG(ERROR) << "Unable to listen for connection requests at TCP address at port: " << port;
        return nullptr;
    }
    */

    return server_socket;
}

int main(int argc, char *argv[])
{
    init_signals();

    // Check for version query first, handle and exit if requested.
    std::string module_description;
    std::ofstream versionfile;
    if (beerocks::version::handle_version_query(argc, argv, module_description)) {
        return 0;
    }

    //get command line options
    if (!parse_arguments(argc, argv)) {
        std::cout << "Usage: " << argv[0] << " -k {kill master}" << std::endl;
        return 1;
    }

    // read master config file
    std::string master_config_file_path =
        "./" + std::string(BEEROCKS_CONTROLLER) + ".conf"; //search first in current directory
    beerocks::config_file::sConfigMaster beerocks_master_conf;
    if (!beerocks::config_file::read_master_config_file(master_config_file_path,
                                                        beerocks_master_conf)) {
        master_config_file_path = mapf::utils::get_install_path() + "config/" +
                                  std::string(BEEROCKS_CONTROLLER) +
                                  ".conf"; // if not found, search in beerocks path
        if (!beerocks::config_file::read_master_config_file(master_config_file_path,
                                                            beerocks_master_conf)) {
            std::cout << "config file '" << master_config_file_path << "' args error." << std::endl;
            return 1;
        }
    }

    // read slave config file
    std::string slave_config_file_path =
        "./" + std::string(BEEROCKS_AGENT) + ".conf"; //search first in current directory
    beerocks::config_file::sConfigSlave beerocks_slave_conf;
    if (!beerocks::config_file::read_slave_config_file(slave_config_file_path,
                                                       beerocks_slave_conf)) {
        slave_config_file_path = mapf::utils::get_install_path() + "config/" +
                                 std::string(BEEROCKS_AGENT) +
                                 ".conf"; // if not found, search in beerocks path
        if (!beerocks::config_file::read_slave_config_file(slave_config_file_path,
                                                           beerocks_slave_conf)) {
            std::cout << "config file '" << slave_config_file_path << "' args error." << std::endl;
            return 1;
        }
    }

    std::string base_master_name = std::string(BEEROCKS_CONTROLLER);

    //kill running master
    beerocks::os_utils::kill_pid(beerocks_master_conf.temp_path, base_master_name);

    // only kill and exit
    if (s_kill_master) {
        return 0;
    }

    //init logger
    beerocks::logging logger(base_master_name, beerocks_master_conf.sLog);
    s_pLogger = &logger;
    logger.apply_settings();
    LOG(INFO) << std::endl
              << "Running " << base_master_name << " Version " << BEEROCKS_VERSION << " Build date "
              << BEEROCKS_BUILD_DATE << std::endl
              << std::endl;
    beerocks::version::log_version(argc, argv);
    versionfile.open(beerocks_master_conf.temp_path + "beerocks_master_version");
    versionfile << BEEROCKS_VERSION << std::endl << BEEROCKS_REVISION;
    versionfile.close();

    // Redirect stdout / stderr
    if (logger.get_log_files_enabled()) {
        beerocks::os_utils::redirect_console_std(beerocks_master_conf.sLog.files_path +
                                                 base_master_name + "_std.log");
    }

    //write pid file
    beerocks::os_utils::write_pid_file(beerocks_master_conf.temp_path, base_master_name);
    std::string pid_file_path =
        beerocks_master_conf.temp_path + "pid/" + base_master_name; // for file touching

    // fill master configuration
    son::db::sDbMasterConfig master_conf;
    fill_master_config(master_conf, beerocks_master_conf);

    // Create application event loop to wait for blocking I/O operations.
    auto event_loop = std::make_shared<beerocks::EventLoopImpl>();
    LOG_IF(!event_loop, FATAL) << "Unable to create event loop!";

    // Create parser for CMDU messages received through a stream-oriented socket.
    auto cmdu_parser = std::make_shared<beerocks::net::CmduParserStreamImpl>();
    LOG_IF(!cmdu_parser, FATAL) << "Unable to create CMDU parser!";

    // Create serializer for CMDU messages to be sent through a stream-oriented socket.
    auto cmdu_serializer = std::make_shared<beerocks::net::CmduSerializerStreamImpl>();
    LOG_IF(!cmdu_serializer, FATAL) << "Unable to create CMDU serializer!";

    std::string uds_path = beerocks_slave_conf.temp_path + "/" + std::string(BEEROCKS_MASTER_UDS);
    auto uds_address     = create_uds_address(uds_path);
    LOG_IF(!uds_address, FATAL) << "Unable to create UDS server address!";

    auto server_socket = create_server_socket(*uds_address);
    LOG_IF(!server_socket, FATAL) << "Unable to create UDS server socket!";

    // Create server to exchange CMDU messages with clients connected through a UDS socket
    auto cmdu_server = std::make_unique<beerocks::CmduServerImpl>(
        std::move(server_socket), cmdu_parser, cmdu_serializer, event_loop);
    LOG_IF(!cmdu_server, FATAL) << "Unable to create CMDU server!";

    std::string master_uds = beerocks_master_conf.temp_path + std::string(BEEROCKS_MASTER_UDS);
    beerocks::net::network_utils::iface_info bridge_info;
    auto &bridge_iface = beerocks_slave_conf.bridge_iface;
    if (beerocks::net::network_utils::get_iface_info(bridge_info, bridge_iface) != 0) {
        LOG(ERROR) << "Failed reading addresses from the bridge!";
        return 0;
    }

    son::db master_db(master_conf, logger, bridge_info.mac);
    // diagnostics_thread diagnostics(master_db);

    // UCC server must be created in certification mode only and if a valid TCP port has been set
    std::unique_ptr<beerocks::UccServer> ucc_server;
    if (master_db.setting_certification_mode() && (master_db.config.ucc_listener_port != 0)) {

        // Create parser for UCC command strings received through a message-oriented socket.
        auto ucc_parser = std::make_shared<beerocks::UccParserMessageImpl>();
        LOG_IF(!ucc_parser, FATAL) << "Unable to create UCC parser!";

        // Create serializer for UCC reply strings to be sent through a message-oriented socket.
        auto ucc_serializer = std::make_shared<beerocks::UccSerializerMessageImpl>();
        LOG_IF(!ucc_serializer, FATAL) << "Unable to create UCC serializer!";

        // Create server socket to connect with remote clients
        auto ucc_server_socket = create_ucc_server_socket(master_db.config.ucc_listener_port);
        LOG_IF(!ucc_server_socket, FATAL) << "Unable to create UCC server socket!";

        // Create server to exchange UCC commands and replies with clients connected through the socket
        ucc_server = std::make_unique<beerocks::UccServerImpl>(
            std::move(ucc_server_socket), ucc_parser, ucc_serializer, event_loop);
        LOG_IF(!cmdu_server, FATAL) << "Unable to create CMDU server!";
    }

    son::master_thread son_master(master_uds, master_db, std::move(ucc_server),
                                  std::move(cmdu_server), event_loop);

    if (!son_master.init()) {
        LOG(ERROR) << "son_master.init() ";
        g_running = false;
    }

    auto touch_time_stamp_timeout = std::chrono::steady_clock::now();
    while (g_running) {

        // Handle signals
        if (s_signal) {
            handle_signal();
            continue;
        }

        if (std::chrono::steady_clock::now() > touch_time_stamp_timeout) {
            beerocks::os_utils::touch_pid_file(pid_file_path);
            touch_time_stamp_timeout = std::chrono::steady_clock::now() +
                                       std::chrono::seconds(beerocks::TOUCH_PID_TIMEOUT_SECONDS);
        }

        if (!son_master.work()) {
            break;
        }
    }

    s_pLogger = nullptr;

    son_master.stop();

    return 0;
}
