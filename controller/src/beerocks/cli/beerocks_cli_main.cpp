/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "beerocks_cli.h"
#include "beerocks_cli_bml.h"
#include "beerocks_cli_proxy.h"
#include "beerocks_cli_socket.h"

#include <bcl/beerocks_config_file.h>
#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_os_utils.h>
#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_version.h>
#include <easylogging++.h>
#include <mapf/common/utils.h>

#include <chrono>

// Do not use this macro anywhere else in ire process
// It should only be there in one place in each executable module
BEEROCKS_INIT_BEEROCKS_VERSION

static bool g_running       = true;
static bool g_loop_cmd_exec = false;

#define BML_PREFIX "bml_"

static void clear_screen(void) { std::cout << "\033[2J"; }

// static void clear_screen_above_cursor(void)
// {
//     std::cout << "\033[1J";
// }

static void set_cursor(int n, int m)
{
    // (n,m) = (1,1) -> top left corner
    std::cout << "\033[" << n << ";" << m << "H";
}

static void sigterm_handler(int signum)
{
    fclose(stdin);
    g_running = false;
}

// Invoked when sigint is invoked
static void sigint_handler(int signum)
{
    if (g_loop_cmd_exec) {
        g_loop_cmd_exec = false;
        clear_screen();
        set_cursor(1, 1);
        std::cout << "Stopped..." << std::endl << std::endl;
    } else {
        fclose(stdin);
        g_running = false;
    }
}

// Initialize the calls to handle Ctrl+C and Ctrl+x
static void init_signals()
{
    struct sigaction sigterm_action;
    sigterm_action.sa_handler = sigterm_handler;
    sigemptyset(&sigterm_action.sa_mask);
    sigterm_action.sa_flags = 0;
    sigaction(SIGTERM, &sigterm_action, NULL);

    struct sigaction sigint_action;
    sigint_action.sa_handler = sigint_handler;
    sigemptyset(&sigint_action.sa_mask);
    sigint_action.sa_flags = 0;
    sigaction(SIGINT, &sigint_action, NULL);
}

static int repeated_cmd_parser(std::string &cmd)
{
    // searching for special signs to recognize repeated mode
    int executions     = 1; // -1 = inf , other = num of executions
    g_loop_cmd_exec    = false;
    auto commandTokens = beerocks::string_utils::str_split(cmd, ' ');
    cmd                = std::string();
    std::string::size_type pos;
    std::string num_str;
    for (auto token = commandTokens.begin(); token != commandTokens.end(); ++token) {
        if ((pos = token->find("*")) != std::string::npos) {
            num_str         = token->substr(pos + sizeof('*'));
            executions      = beerocks::string_utils::stoi(num_str);
            executions      = (executions > 0) ? executions : 0;
            g_loop_cmd_exec = true;
            commandTokens.erase(token);
            break;

        } else if ((token->find("!")) != std::string::npos) {
            executions      = -1;
            g_loop_cmd_exec = true;
            commandTokens.erase(token);
            break;
        }
    }

    for (auto &token : commandTokens) {
        cmd += token + " ";
    }

    if (cmd.back() == ' ') {
        cmd.pop_back(); // remove last space
    }

    return executions;
}

static int cli_non_interactive(std::string path, std::string tmp_path, std::string ip,
                               std::string command_string)
{
    int status_code = 0;
    beerocks::cli_socket cli_soc(tmp_path, ip);
    beerocks::cli_bml cli_bml(path);
    beerocks::cli *cli_ptr;
    std::string bml_prefix(BML_PREFIX);

    if (command_string.compare(0, bml_prefix.size(), bml_prefix)) { // Socket
        cli_ptr = &cli_soc;
        if (!cli_soc.connect()) {
            std::cout << "cli_socket: Can't connect to master, exit..." << std::endl;
            return 1;
        }
        if (!cli_soc.start()) {
            std::cout << "cli_socket: Can't start cli, exit" << std::endl;
            return 1;
        }
    } else { // BML
        cli_ptr = &cli_bml;
        if (!cli_bml.connect()) {
            std::cout << "cli_bml: Can't connect to master, exit..." << std::endl;
            return 1;
        }
    }

    if (-1 == cli_ptr->multiple_commands(command_string)) {
        status_code = 1;
    }

    // Max timeout according to CAPI specifications is 120 seconds
    auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    while (cli_bml.is_pending_response()) {
        if (std::chrono::steady_clock::now() > timeout) {
            break;
        }
    }

    cli_soc.stop();
    cli_bml.stop();
    cli_soc.disconnect();
    cli_bml.disconnect();

    return status_code;
}

static bool getline_interactive(std::string &strBuf)
{
    const char *prompt = ">>";

    if (!std::cin.good()) {
        return false;
    }
    std::cout << prompt;
    getline(std::cin, strBuf);
    if (strBuf.empty() && !std::cin) {
        return false;
    } else {
        return true;
    }
}

static void cli_interactive(std::string path, std::string tmp_path, std::string ip)
{
    std::cout << "Welcome to BeeRocks CLI " << BEEROCKS_VERSION << " Build date "
              << BEEROCKS_BUILD_DATE << std::endl;
    std::cout << "Enter 'help' for help, 'exit' to exit" << std::endl;

    beerocks::cli_bml cli_bml(path);
    int is_onboarding = -1;

    if (!cli_bml.connect()) {
        std::cout << "cli_bml: Can't connect to BML, exit..." << std::endl;
    } else {
        std::cout << "Connected to BeeRocks BML CLI." << std::endl;
        is_onboarding = cli_bml.get_onboarding_status();
    }

    beerocks::cli_socket cli_soc(tmp_path, ip);
    beerocks::cli *cli_ptr;
    if (is_onboarding == 0) {
        if (!cli_soc.connect()) {
            std::cout << "cli_socket: Can't connect to master." << std::endl;
        } else if (!cli_soc.start()) {
            std::cout << "cli_socket: Can't start cli, exit" << std::endl;
            return;
        } else {
            std::cout << "Connected to BeeRocks Master CLI." << std::endl;
        }
    }

    //read user input and execute functions
    bool quit_request = false;
    std::string bml_prefix(BML_PREFIX);
    std::string strBuf;

    while (g_running && getline_interactive(strBuf)) {
        //parse and call function
        if (!strBuf.empty()) {
            int executions = repeated_cmd_parser(strBuf);

            if (strBuf.compare(0, bml_prefix.size(), bml_prefix)) { // Socket
                cli_ptr = &cli_soc;
            } else { // BML
                cli_ptr = &cli_bml;
            }

            if (cli_ptr->parsedCommandArgumentsLinux(strBuf)) {
                bool exe_cmd = true;
                auto command = cli_ptr->get_command();

                if (!((command.find("connect") != std::string::npos) ||
                      (command.find("help") != std::string::npos) || (command == "q") ||
                      (command == "exit"))) {
                    if (!cli_ptr->is_connected()) {
                        exe_cmd = false;
                        std::cout << "can't execute command, not connected to master." << std::endl;
                    }
                }

                if (exe_cmd) {
                    do {
                        if (executions < 0) {
                            clear_screen();
                            set_cursor(1, 1);
                            std::cout << "PRESS CTRL+C TO STOP (NOT EXIT)" << std::endl
                                      << std::endl;
                        } else if (executions > 1) {
                            std::cout << "PRESS CTRL+C TO STOP (NOT EXIT)" << std::endl
                                      << std::endl;
                        }
                        if (command == "help") {
                            if (is_onboarding == 0) {
                                cli_soc.print_help();
                            }
                            cli_bml.print_help(false);
                        } else {
                            if (cli_ptr->callCommand() < 0) {
                                quit_request = true;
                                break;
                            }
                        }
                        if (--executions) {
                            UTILS_SLEEP_MSEC(1000);
                        }
                    } while (g_running && g_loop_cmd_exec && executions);
                    g_loop_cmd_exec = false;
                }
            }
        }

        if (quit_request) {
            break;
        }
    }

    std::cout << "exit..." << std::endl;

    cli_soc.stop();
    cli_bml.stop();
    cli_soc.disconnect();
    cli_bml.disconnect();
}

static void cli_tcp_proxy(const std::string &temp_path)
{
    std::string master_uds = temp_path + std::string(BEEROCKS_CONTROLLER_UDS);
    beerocks::cli_proxy cli_proxy_thread(master_uds);

    if (!cli_proxy_thread.start()) {
        LOG(ERROR) << "cli_proxy.start() failed ";
        g_running = false;
    }

    while (g_running) {
        UTILS_SLEEP_MSEC(1000);
    }
    std::cout << "beerocks_cli exit..." << std::endl;
    cli_proxy_thread.stop();
}

int main(int argc, char *argv[])
{
    init_signals();

    int opt;
    enum {
        CLI_PROXY,
        CLI_ANALYZER,
        CLI_NON_INTERACTIVE,
        CLI_INTERACTIVE,
    } cli_role = CLI_INTERACTIVE;

    std::string analyzer_ip;
    std::string ip;
    std::string command_string;

    while ((opt = getopt(argc, argv, "pi:c:a:")) != -1) {
        switch (opt) {
        case 'p': {
            cli_role = CLI_PROXY;
            break;
        }
        case 'i': {
            ip = std::string(optarg);
            break;
        }
        case 'c': {
            command_string = std::string(optarg);
            cli_role       = CLI_NON_INTERACTIVE;
            break;
        }
        case 'a': {
            cli_role    = CLI_ANALYZER;
            analyzer_ip = std::string(optarg);
            break;
        }
        default: { /* '?' */
            return 1;
        }
        }
    }

    //read slave config file
    std::string config_file_path =
        mapf::utils::get_install_path() + "config/" + std::string(BEEROCKS_AGENT) + ".conf";
    beerocks::config_file::sConfigSlave beerocks_slave_conf;
    if (!beerocks::config_file::read_slave_config_file(config_file_path, beerocks_slave_conf)) {
        std::cout << "config file '" << config_file_path << "' args error." << std::endl;
        return 1;
    }

    int status_return = 0;

    // Override standard output to "true" since CLI must print everything to the console
    beerocks_slave_conf.sLog.stdout_enabled = "true";

    // Init logger
    beerocks::logging cli_logger("beerocks_cli", beerocks_slave_conf.sLog);
    cli_logger.apply_settings();

    switch (cli_role) {
    case CLI_PROXY: {
        cli_tcp_proxy(beerocks_slave_conf.temp_path);
        break;
    }
    case CLI_NON_INTERACTIVE: {
        status_return = cli_non_interactive(mapf::utils::get_install_path() + "config/",
                                            beerocks_slave_conf.temp_path, ip, command_string);
        break;
    }
    case CLI_ANALYZER: {
        beerocks::cli_bml cli_bml(mapf::utils::get_install_path() + "config/");
        cli_bml.analyzer_init(analyzer_ip);
        break;
    }
    default: // CLI_INTERACTIVE
        cli_interactive(mapf::utils::get_install_path() + "config/", beerocks_slave_conf.temp_path,
                        ip);
        break;
    }

    return status_return;
}
