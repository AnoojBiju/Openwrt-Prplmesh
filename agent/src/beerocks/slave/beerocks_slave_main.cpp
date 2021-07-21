/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "backhaul_manager/backhaul_manager.h"
#include "platform_manager/platform_manager.h"
#include "son_slave_thread.h"

#include <bcl/beerocks_cmdu_client_factory_factory.h>
#include <bcl/beerocks_cmdu_server_factory.h>
#include <bcl/beerocks_config_file.h>
#include <bcl/beerocks_event_loop_impl.h>
#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_timer_factory_impl.h>
#include <bcl/beerocks_timer_manager_impl.h>
#include <bcl/beerocks_ucc_server_factory.h>
#include <bcl/beerocks_utils.h>
#include <bcl/beerocks_version.h>
#include <bcl/network/network_utils.h>
#include <bcl/network/sockets_impl.h>
#include <btl/broker_client_factory_factory.h>
#include <mapf/common/utils.h>

#include <easylogging++.h>

#ifdef ENABLE_NBAPI

#include "ambiorix_impl.h"

#ifndef AMBIORIX_BACKEND_PATH
#define AMBIORIX_BACKEND_PATH "/usr/bin/mods/amxb/mod-amxb-ubus.so"
#endif // AMBIORIX_BACKEND_PATH

#ifndef AMBIORIX_BUS_URI
#define AMBIORIX_BUS_URI "ubus:"
#endif // AMBIORIX_BUS_URI

#ifndef AGENT_DATAMODEL_PATH
#define AGENT_DATAMODEL_PATH "config/odl/agent.odl"
#endif // AGENT_DATAMODEL_PATH

#endif

#include "ambiorix_dummy.h"

// Do not use this macro anywhere else in ire process
// It should only be there in one place in each executable module
BEEROCKS_INIT_BEEROCKS_VERSION

static bool g_running = true;
static int s_signal   = 0;

// Pointer to logger instance
static std::vector<std::shared_ptr<beerocks::logging>> g_loggers;

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

        for (auto &logger : g_loggers) {
            CLOG(INFO, logger->get_logger_id()) << "LOG Roll Signal!";
            logger->apply_settings();
            CLOG(INFO, logger->get_logger_id()) << "--- Start of file after roll ---";
        }
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
    while ((opt = getopt(argc, argv, "q:")) != -1) {
        switch (opt) {
        case 'q': // query platform: is_master, is_gateway, is_onboarding
        {
            std::string request{optarg};
            std::cout << std::endl
                      << request << "=" << beerocks::PlatformManager::query_db(request)
                      << std::endl;
            exit(0);
        }
        case '?': {
            return false;
        }
        }
    }
    return true;
}

static std::string get_sta_iface_from_hostap_iface(const std::string &hostap_iface)
{
    // read the sta_iface from bpl and verify it is available
    char sta_iface_str[BPL_IFNAME_LEN];
    std::string sta_iface;

    if (beerocks::bpl::cfg_get_sta_iface(hostap_iface.c_str(), sta_iface_str) < 0) {
        LOG(ERROR) << "failed to read sta_iface for slave ";
        return std::string();
    } else {
        sta_iface = std::string(sta_iface_str);
        if (!beerocks::net::network_utils::linux_iface_exists(sta_iface)) {
            LOG(DEBUG) << "sta iface " << sta_iface << " does not exist, clearing it from config";
            sta_iface.clear();
        }
    }
    return sta_iface;
}

static void fill_son_slave_config(const beerocks::config_file::sConfigSlave &beerocks_slave_conf,
                                  son::slave_thread::sSlaveConfig &son_slave_conf,
                                  const std::string &hostap_iface, int slave_num)
{
    son_slave_conf.temp_path = beerocks_slave_conf.temp_path;
    son_slave_conf.vendor    = beerocks_slave_conf.vendor;
    son_slave_conf.model     = beerocks_slave_conf.model;
    son_slave_conf.ucc_listener_port =
        (!beerocks_slave_conf.ucc_listener_port.empty())
            ? beerocks::string_utils::stoi(beerocks_slave_conf.ucc_listener_port)
            : static_cast<uint16_t>(beerocks::eGlobals::UCC_LISTENER_PORT);
    son_slave_conf.bridge_iface             = beerocks_slave_conf.bridge_iface;
    son_slave_conf.backhaul_preferred_bssid = beerocks_slave_conf.backhaul_preferred_bssid;
    son_slave_conf.enable_repeater_mode =
        beerocks_slave_conf.enable_repeater_mode[slave_num] == "1";
    son_slave_conf.hostap_iface_type = beerocks::utils::get_iface_type_from_string(
        beerocks_slave_conf.hostap_iface_type[slave_num]);
    son_slave_conf.hostap_iface = hostap_iface;
    son_slave_conf.hostap_ant_gain =
        (!beerocks_slave_conf.hostap_ant_gain[slave_num].empty())
            ? beerocks::string_utils::stoi(beerocks_slave_conf.hostap_ant_gain[slave_num])
            : 0;
    son_slave_conf.backhaul_wireless_iface =
        get_sta_iface_from_hostap_iface(son_slave_conf.hostap_iface);
    son_slave_conf.backhaul_wireless_iface_filter_low =
        (!beerocks_slave_conf.sta_iface_filter_low[slave_num].empty())
            ? beerocks::string_utils::stoi(beerocks_slave_conf.sta_iface_filter_low[slave_num])
            : 0;

    // disable stopping on failure initially. Later on, it will be read from BPL as part of
    // cACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE
    son_slave_conf.stop_on_failure_attempts = 0;
}

static std::shared_ptr<beerocks::logging>
init_logger(const std::string &file_name, const beerocks::config_file::SConfigLog &log_config,
            int argc, char **argv, const std::string &logger_id = std::string())
{
    auto logger = std::make_shared<beerocks::logging>(file_name, log_config, logger_id);
    if (!logger) {
        std::cout << "Failed to allocated logger to " << file_name;
        return std::shared_ptr<beerocks::logging>();
    }
    logger->apply_settings();
    CLOG(INFO, logger->get_logger_id())
        << std::endl
        << "Running " << file_name << " Version " << BEEROCKS_VERSION << " Build date "
        << BEEROCKS_BUILD_DATE << std::endl
        << std::endl;
    beerocks::version::log_version(argc, argv, logger->get_logger_id());

    // Redirect stdout / stderr to file
    if (logger->get_log_files_enabled()) {
        beerocks::os_utils::redirect_console_std(log_config.files_path + file_name + "_std.log");
    }

    return logger;
}

static int system_hang_test(const beerocks::config_file::sConfigSlave &beerocks_slave_conf,
                            int argc, char *argv[])
{
    std::string name = std::string("system_hang_test");

    // Init logger
    auto logger = init_logger(name, beerocks_slave_conf.sLog, argc, argv);
    if (!logger) {
        return 1;
    }

    // Write pid file
    beerocks::os_utils::write_pid_file(beerocks_slave_conf.temp_path, name);
    std::string pid_file_path = beerocks_slave_conf.temp_path + "pid/" + name; // for file touching

    // Initialize timers
    auto touch_time_stamp_timeout = std::chrono::steady_clock::now();
    auto error_time_stamp_timeout = std::chrono::steady_clock::now();

    int pid = getpid();

    while (g_running) {
        // Handle signals
        if (s_signal) {
            handle_signal();
            continue;
        }
        if (std::chrono::steady_clock::now() > touch_time_stamp_timeout) {
            LOG(INFO) << "system_hang_test, pid=" << pid;
            beerocks::os_utils::touch_pid_file(pid_file_path);
            touch_time_stamp_timeout =
                std::chrono::steady_clock::now() +
                std::chrono::seconds(beerocks::TOUCH_PID_TIMEOUT_SECONDS) / 4;

            auto err_time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - error_time_stamp_timeout)
                                     .count();
            if (err_time_diff > ((1000 * beerocks::TOUCH_PID_TIMEOUT_SECONDS) / 2)) {
                LOG(ERROR) << int(err_time_diff)
                           << " msec have passed between the two last prints!";
            }
            error_time_stamp_timeout = std::chrono::steady_clock::now();
        }
        UTILS_SLEEP_MSEC(100);
    }

    return 0;
}

static std::shared_ptr<son::slave_thread>
start_son_slave_thread(int slave_num,
                       const beerocks::config_file::sConfigSlave &beerocks_slave_conf,
                       const std::string &fronthaul_iface, int argc, char *argv[])
{
    std::string base_slave_name = std::string(BEEROCKS_AGENT) + "_" + fronthaul_iface;

    // Init logger
    auto logger =
        init_logger(base_slave_name, beerocks_slave_conf.sLog, argc, argv, base_slave_name);
    if (!logger) {
        return nullptr;
    }
    g_loggers.push_back(logger);

    // Fill configuration
    son::slave_thread::sSlaveConfig son_slave_conf;
    fill_son_slave_config(beerocks_slave_conf, son_slave_conf, fronthaul_iface, slave_num);

    // Disable stopping on failure initially. Later on, it will be read from BPL as part of
    // cACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE
    son_slave_conf.stop_on_failure_attempts = 0;

    auto son_slave = std::make_shared<son::slave_thread>(son_slave_conf, *logger);
    if (!son_slave) {
        CLOG(ERROR, logger->get_logger_id()) << "son::slave_thread allocating has failed!";
        return nullptr;
    }

    if (!son_slave->start()) {
        CLOG(ERROR, logger->get_logger_id()) << "son_slave.start() has failed";
        return nullptr;
    }

    return son_slave;
}

static int run_beerocks_slave(beerocks::config_file::sConfigSlave &beerocks_slave_conf,
                              const std::unordered_map<int, std::string> &interfaces_map, int argc,
                              char *argv[])
{
    std::string base_agent_name = std::string(BEEROCKS_AGENT);

    // Init logger
    auto agent_logger = init_logger(base_agent_name, beerocks_slave_conf.sLog, argc, argv);
    if (!agent_logger) {
        return 1;
    }
    g_loggers.push_back(agent_logger);

    // Write pid file
    beerocks::os_utils::write_pid_file(beerocks_slave_conf.temp_path, base_agent_name);
    std::string pid_file_path =
        beerocks_slave_conf.temp_path + "pid/" + base_agent_name; // for file touching

    std::set<std::string> slave_ap_ifaces;
    for (auto &elm : interfaces_map) {
        if (!elm.second.empty()) {
            slave_ap_ifaces.insert(elm.second);
        }
    }

    // Create application event loop to wait for blocking I/O operations.
    auto event_loop = std::make_shared<beerocks::EventLoopImpl>();
    LOG_IF(!event_loop, FATAL) << "Unable to create event loop!";

    // Create timer factory to create instances of timers.
    auto timer_factory = std::make_shared<beerocks::TimerFactoryImpl>();
    LOG_IF(!timer_factory, FATAL) << "Unable to create timer factory!";

    // Create timer manager to help using application timers.
    auto timer_manager = std::make_shared<beerocks::TimerManagerImpl>(timer_factory, event_loop);
    LOG_IF(!timer_manager, FATAL) << "Unable to create timer manager!";

    // Create UDS address where the server socket will listen for incoming connection requests.
    std::string platform_manager_uds_path =
        beerocks_slave_conf.temp_path + "/" + std::string(BEEROCKS_PLAT_MGR_UDS);
    auto platform_manager_uds_address =
        beerocks::net::UdsAddress::create_instance(platform_manager_uds_path);
    LOG_IF(!platform_manager_uds_address, FATAL)
        << "Unable to create UDS server address for platform manager!";

    // Create server to exchange CMDU messages with clients connected through a UDS socket
    auto platform_manager_cmdu_server =
        beerocks::CmduServerFactory::create_instance(platform_manager_uds_address, event_loop);
    LOG_IF(!platform_manager_cmdu_server, FATAL)
        << "Unable to create CMDU server for platform manager!";

#ifdef ENABLE_NBAPI
    auto agent_dm_path = mapf::utils::get_install_path() + AGENT_DATAMODEL_PATH;
    auto amb_dm_obj    = std::make_shared<beerocks::nbapi::AmbiorixImpl>(
        event_loop, std::vector<beerocks::nbapi::sActionsCallback>(),
        std::vector<beerocks::nbapi::sEvents>(), std::vector<beerocks::nbapi::sFunctions>());
    LOG_IF(!amb_dm_obj, FATAL) << "Unable to create Ambiorix!";
    LOG_IF(!amb_dm_obj->init(AMBIORIX_BACKEND_PATH, AMBIORIX_BUS_URI, agent_dm_path), FATAL)
        << "Unable to init ambiorix object!";
#else
    auto amb_dm_obj = std::make_shared<beerocks::nbapi::AmbiorixDummy>();
#endif //ENABLE_NBAPI

    {
        auto db = beerocks::AgentDB::get();

        db->init_data_model(amb_dm_obj);

        if (!beerocks::bpl::bpl_cfg_get_backhaul_wire_iface(db->ethernet.wan.iface_name)) {
            LOG(ERROR) << "Failed reading 'backhaul_wire_iface'";
            return false;
        }
        // Destroy `db` to unlock it.
    }

    beerocks::PlatformManager platform_manager(beerocks_slave_conf, interfaces_map, *agent_logger,
                                               std::move(platform_manager_cmdu_server),
                                               timer_manager, event_loop);

    // Start platform manager
    LOG_IF(!platform_manager.start(), FATAL) << "Unable to start platform manager!";

    // Read the number of failures allowed before stopping agent from platform configuration
    int stop_on_failure_attempts = beerocks::bpl::cfg_get_stop_on_failure_attempts();

    // The platform manager updates the beerocks_slave_conf.sta_iface in the init stage
    std::set<std::string> slave_sta_ifaces;
    // Check if there is any sta_iface at all:
    LOG_IF(std::end(beerocks_slave_conf.sta_iface) ==
               std::find_if(std::begin(beerocks_slave_conf.sta_iface),
                            std::end(beerocks_slave_conf.sta_iface),
                            [&](std::string &s) { return !s.empty(); }),
           WARNING)
        << "No slave sta ifaces!";
    for (int slave_num = 0; slave_num < beerocks::IRE_MAX_SLAVES; slave_num++) {
        if (!beerocks_slave_conf.sta_iface[slave_num].empty()) {
            slave_sta_ifaces.insert(beerocks_slave_conf.sta_iface[slave_num]);
        }
    }

    // Create UDS address where the server socket will listen for incoming connection requests.
    std::string backhaul_manager_uds_path =
        beerocks_slave_conf.temp_path + "/" + std::string(BEEROCKS_BACKHAUL_MGR_UDS);
    auto backhaul_manager_uds_address =
        beerocks::net::UdsAddress::create_instance(backhaul_manager_uds_path);
    LOG_IF(!backhaul_manager_uds_address, FATAL)
        << "Unable to create UDS server address for backhaul manager!";

    // Create server to exchange CMDU messages with clients connected through a UDS socket
    auto backhaul_manager_cmdu_server =
        beerocks::CmduServerFactory::create_instance(backhaul_manager_uds_address, event_loop);
    LOG_IF(!backhaul_manager_cmdu_server, FATAL)
        << "Unable to create CMDU server for backhaul manager!";

    // UCC server must be created if all the three following conditions are met:
    // - Device has been configured to work in certification mode
    // - A valid TCP port has been set
    // - The controller is not running in this device
    std::unique_ptr<beerocks::UccServer> ucc_server;
    bool certification_mode = beerocks::bpl::cfg_get_certification_mode();
    bool local_controller   = beerocks::bpl::cfg_is_master();
    uint16_t port           = beerocks::string_utils::stoi(beerocks_slave_conf.ucc_listener_port);
    if (certification_mode && (port != 0) && (!local_controller)) {

        LOG(INFO) << "Certification mode enabled (listening on port " << port << ")";

        // Create server to exchange UCC commands and replies with clients connected through the socket
        ucc_server = beerocks::UccServerFactory::create_instance(port, event_loop);
        LOG_IF(!ucc_server, FATAL) << "Unable to create UCC server!";
    }

    // Create CMDU client factory to create CMDU clients connected to CMDU server running in
    // platform manager when requested
    auto platform_manager_cmdu_client_factory =
        beerocks::create_cmdu_client_factory(platform_manager_uds_path, event_loop);
    LOG_IF(!platform_manager_cmdu_client_factory, FATAL) << "Unable to create CMDU client factory!";

    // Create broker client factory to create broker clients when requested
    std::string broker_uds_path =
        beerocks_slave_conf.temp_path + "/" + std::string(BEEROCKS_BROKER_UDS);
    auto broker_client_factory =
        beerocks::btl::create_broker_client_factory(broker_uds_path, event_loop);
    LOG_IF(!broker_client_factory, FATAL) << "Unable to create broker client factory!";

    beerocks::BackhaulManager backhaul_manager(
        beerocks_slave_conf, slave_ap_ifaces, slave_sta_ifaces, stop_on_failure_attempts,
        std::move(broker_client_factory), std::move(platform_manager_cmdu_client_factory),
        std::move(ucc_server), std::move(backhaul_manager_cmdu_server), timer_manager, event_loop);

    // Start backhaul manager
    LOG_IF(!backhaul_manager.start(), FATAL) << "Unable to start backhaul manager!";

    std::vector<std::shared_ptr<son::slave_thread>> son_slaves;
    for (const auto &iface_element : interfaces_map) {
        auto son_slave_num    = iface_element.first;
        auto &fronthaul_iface = iface_element.second;
        LOG(DEBUG) << "Running son_slave_" << fronthaul_iface;
        auto son_slave =
            start_son_slave_thread(son_slave_num, beerocks_slave_conf, fronthaul_iface, argc, argv);
        if (!son_slave) {
            LOG(ERROR) << "Failed to start son_slave_" << fronthaul_iface;
            return 1;
        }
        son_slaves.push_back(son_slave);
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

        // Check if all son_slave are still running and break on error.
        auto should_break = false;
        for (const auto &son_slave : son_slaves) {
            should_break = !son_slave->is_running();
            if (should_break) {
                break;
            }
        }
        if (should_break) {
            break;
        }

        // Run application event loop and break on error.
        if (event_loop->run() < 0) {
            LOG(ERROR) << "Event loop failure!";
            break;
        }
    }

    for (const auto &son_slave : son_slaves) {
        son_slave->stop();
    }

    LOG(DEBUG) << "backhaul_manager.stop()";
    backhaul_manager.stop();

    LOG(DEBUG) << "platform_manager.stop()";
    platform_manager.stop();

    LOG(DEBUG) << "Bye Bye!";

    return 0;
}

/**
 * @brief Removes the residue files from previous agent process instance.
 *
 * @param path Path to where the agent residual file are located.
 * @param file_name Name of the file to be removed if exist.
 */
static void remove_residual_agent_files(const std::string &path, const std::string &file_name)
{
    int pid_out = -1;
    // If the PID not provided by is-pid-running check.
    if (!beerocks::os_utils::read_pid_file(path, file_name, pid_out)) {
        // If the file doesn't exist or failed to read PID from it - do nothing.
        return;
    }

    // There is no error print to prevent false error prints in case of first boot.
    if (pid_out == -1) {
        return;
    }

    for (int index = 1; index <= beerocks::eBeeRocksIfaceIds::IFACE_TOTAL_VAPS; ++index) {
        // Removes a residual wpa_ctrl files of an old PIDs if exists.
        std::stringstream ss;
        ss << "wpa_ctrl_" << pid_out << "-" << index;
        beerocks::os_utils::remove_residual_files(std::string("/tmp/"), ss.str());
    }
}

int main(int argc, char *argv[])
{
    std::cout << "Beerocks Agent Process Start" << std::endl;

    init_signals();

    // Check for version query first, handle and exit if requested.
    std::string module_description;
    if (beerocks::version::handle_version_query(argc, argv, module_description)) {
        return 0;
    }

    //get command line options
    if (!parse_arguments(argc, argv)) {
        std::cout << "Usage: " << argv[0] << std::endl;
        return 1;
    }

    // read slave config file
    std::string slave_config_file_path =
        CONF_FILES_WRITABLE_PATH + std::string(BEEROCKS_AGENT) +
        ".conf"; //search first in platform-specific default directory
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

    // beerocks system hang tester
    if (beerocks_slave_conf.enable_system_hang_test == "1") {

        pid_t pid = fork();
        if (pid == 0) {
            // child process
            return system_hang_test(beerocks_slave_conf, argc, argv);
        }
    }

    beerocks::bpl::BPL_WLAN_IFACE interfaces[beerocks::IRE_MAX_SLAVES] = {0};
    int num_of_interfaces                                              = beerocks::IRE_MAX_SLAVES;
    if (beerocks::bpl::cfg_get_all_prplmesh_wifi_interfaces(interfaces, &num_of_interfaces)) {
        std::cout << "ERROR: Failed to read interfaces map" << std::endl;
        return 1;
    }

    std::string mandatory_interfaces;
    std::vector<std::string> mandatory_interfaces_vec;
    // Read the mandatory interfaces list from config and parse it if not empty
    if (beerocks::bpl::bpl_cfg_get_mandatory_interfaces(mandatory_interfaces)) {
        if (!mandatory_interfaces.empty()) {
            mandatory_interfaces_vec = beerocks::string_utils::str_split(mandatory_interfaces, ',');
        }
    }

    // Create unordered_map of interfaces.
    // This map contains all the radios that we expect to be there.
    // We don't go to operational until the slaves for these interfaces are operational.
    std::unordered_map<int, std::string> interfaces_map;
    for (int i = 0; i < num_of_interfaces; i++) {
        // If interface is mandatory
        if (std::find(mandatory_interfaces_vec.begin(), mandatory_interfaces_vec.end(),
                      interfaces[i].ifname) != mandatory_interfaces_vec.end()) {
            interfaces_map[interfaces[i].radio_num] = std::string(interfaces[i].ifname);
        } else if (beerocks::net::network_utils::linux_iface_exists(interfaces[i].ifname)) {
            // if interface is not mandatory and exists
            interfaces_map[interfaces[i].radio_num] = std::string(interfaces[i].ifname);
        }
    }

    if (interfaces_map.empty()) {
        std::cout << "INFO: No radio interfaces are available" << std::endl;
        return 0;
    }

    // killall running slave
    beerocks::os_utils::kill_pid(beerocks_slave_conf.temp_path + "pid/",
                                 std::string(BEEROCKS_AGENT));

    // Remove any residual agent files not cleared by previous instance
    remove_residual_agent_files(beerocks_slave_conf.temp_path, std::string(BEEROCKS_AGENT));

    // backhaul/platform manager slave
    return run_beerocks_slave(beerocks_slave_conf, interfaces_map, argc, argv);
}
