/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "../common/utils/utils.h"
#include "../common/utils/utils_net.h"
#include "bpl_cfg_linux.h"
#include <bcl/beerocks_string_utils.h>
#include <bpl/bpl_cfg.h>
#include <mapf/common/logger.h>
#include <mapf/common/utils.h>

#include <tlvf/WSC/eWscAuth.h>
#include <tlvf/WSC/eWscEncr.h>

using namespace mapf;

#define PLATFORM_DB_PATH mapf::utils::get_install_path() + "share/prplmesh_platform_db"

#ifndef PLATFORM_DB_PATH_TEMP
#define PLATFORM_DB_PATH_TEMP "/tmp/prplmesh_platform_db"
#endif

namespace beerocks {
namespace bpl {

/**
 * @brief Returns the name of the configuration file to use.
 *
 * Configuration file can be either PLATFORM_DB_PATH_TEMP or PLATFORM_DB_PATH, the first that proves
 * to exist in that order.
 *
 * If none exists, then returns false and sets the file name to the last one tried.
 *
 * @param file_name Name of the configuration file to use.
 * @return true on success and false otherwise.
 */
static bool cfg_get_file_name(std::string &file_name)
{
    // Return the first existing file in the array.
    const std::string file_names[]{PLATFORM_DB_PATH_TEMP, PLATFORM_DB_PATH};

    for (const auto &name : file_names) {
        std::ifstream file(name);
        if (file) {
            file_name = name;
            return true;
        }
    }

    // None of the files in the array could be found.
    // Return the last file name tried.
    return false;
}

bool cfg_get_params(std::unordered_map<std::string, std::string> &parameters,
                    std::function<bool(const std::string &name)> filter)
{
    std::string file_name;
    if (!cfg_get_file_name(file_name)) {
        MAPF_ERR("Failed opening file " << file_name);
        return false;
    }

    std::ifstream file(file_name);

    std::string line;
    while (std::getline(file, line)) {
        utils::trim(line);
        if (line.empty()) {
            continue; // Empty line
        }
        if (line.at(0) == '#') {
            continue; // Commented line
        }

        auto pos = line.find("#");
        if (pos != std::string::npos) {
            line.erase(pos, line.size());
            utils::rtrim(line);
        }

        pos = line.find("=");
        if (pos == std::string::npos) {
            continue; // Not a name=value
        }

        std::string name = line.substr(0, pos);
        if (!filter || filter(name)) {
            std::string value = line.substr(pos + 1, line.size());
            parameters[name]  = value;
        }
    }

    return true;
}

bool cfg_set_params(const std::unordered_map<std::string, std::string> &parameters)
{
    std::string file_name;
    if (!cfg_get_file_name(file_name)) {
        MAPF_ERR("Failed opening file " << file_name);
        return false;
    }

    std::ofstream file(file_name);

    for (const auto &parameter : parameters) {
        file << parameter.first << "=" << parameter.second << std::endl;
    }

    file.close();
    if (!file.good()) {
        MAPF_ERR("Failed writing to file " << file_name);
        return false;
    }

    return true;
}

bool cfg_get_param(const std::string &name, std::string &value)
{
    std::unordered_map<std::string, std::string> parameters;
    auto filter = [name](const std::string &n) { return n == name; };

    if (!cfg_get_params(parameters, filter)) {
        return false;
    }

    auto it = parameters.find(name);
    if (it == parameters.end()) {
        return false;
    }
    value = it->second;
    return true;
}

int cfg_get_param_int(const std::string &param, int &value)
{
    std::string str_value;

    if (!cfg_get_param(param, str_value)) {
        MAPF_ERR("Failed reading param " << param);
        return RETURN_ERR;
    }

    value = utils::stoi(str_value);

    return RETURN_OK;
}

int cfg_is_enabled() { return 1; }

int cfg_is_master()
{
    switch (cfg_get_management_mode()) {
    case BPL_MGMT_MODE_MULTIAP_CONTROLLER_AGENT:
        return 1;
    case BPL_MGMT_MODE_MULTIAP_CONTROLLER:
        return 1;
    case BPL_MGMT_MODE_MULTIAP_AGENT:
        return 0;
    case BPL_MGMT_MODE_NOT_MULTIAP:
        return (cfg_get_operating_mode() == BPL_OPER_MODE_GATEWAY) ? 1 : 0;
    default:
        return RETURN_ERR;
    }
}

int cfg_get_management_mode()
{
    std::string mgmt_mode;
    if (!cfg_get_param("management_mode", mgmt_mode)) {
        MAPF_ERR("cfg_get_management_mode: Failed to read management_mode");
        return RETURN_ERR;
    }

    if (mgmt_mode == "Multi-AP-Controller-and-Agent") {
        return BPL_MGMT_MODE_MULTIAP_CONTROLLER_AGENT;
    } else if (mgmt_mode == "Multi-AP-Controller") {
        return BPL_MGMT_MODE_MULTIAP_CONTROLLER;
    } else if (mgmt_mode == "Multi-AP-Agent") {
        return BPL_MGMT_MODE_MULTIAP_AGENT;
    } else if (mgmt_mode == "Not-Multi-AP") {
        return BPL_MGMT_MODE_NOT_MULTIAP;
    }

    MAPF_ERR("cfg_get_management_mode: Unexpected management_mode");
    return RETURN_ERR;
}

int cfg_get_operating_mode()
{
    std::string op_mode;
    if (!cfg_get_param("operating_mode", op_mode)) {
        MAPF_ERR("cfg_get_operating_mode: Failed to read operating_mode");
        return RETURN_ERR;
    }

    if (op_mode == "Gateway") {
        return BPL_OPER_MODE_GATEWAY;
    } else if (op_mode == "Gateway-WISP") {
        return BPL_OPER_MODE_GATEWAY_WISP;
    } else if (op_mode == "WDS-Extender") {
        return BPL_OPER_MODE_WDS_EXTENDER;
    } else if (op_mode == "WDS-Repeater") {
        return BPL_OPER_MODE_WDS_REPEATER;
    } else if (op_mode == "L2NAT-Client") {
        return BPL_OPER_MODE_L2NAT_CLIENT;
    }

    MAPF_ERR("cfg_get_operating_mode: Unexpected operating_mode");
    return RETURN_ERR;
}

bool bpl_cfg_get_on_boot_only_scan() { return false; }

int cfg_get_certification_mode()
{
    int retVal = 0;
    std::string certification_mode;
    if (!cfg_get_param("certification_mode", certification_mode)) {
        MAPF_ERR("cfg_get_certification_mode: Failed to read certification_mode");
        retVal = RETURN_ERR;
    } else if (certification_mode == "0") {
        retVal = BPL_CERTIFICATION_MODE_OFF;
    } else {
        // if "0" then disabled, anything else for enabled
        retVal = BPL_CERTIFICATION_MODE_ON;
    }

    return retVal;
}

int cfg_get_load_steer_on_vaps(int num_of_interfaces,
                               char load_steer_on_vaps[BPL_LOAD_STEER_ON_VAPS_LEN])
{
    if (num_of_interfaces < 1) {
        MAPF_ERR("invalid input: max num_of_interfaces value < 1");
        return RETURN_ERR;
    }

    if (!load_steer_on_vaps) {
        MAPF_ERR("invalid input: load_steer_on_vaps is NULL");
        return RETURN_ERR;
    }

    std::string load_steer_on_vaps_str;
    char ifname[BPL_IFNAME_LEN] = {0};
    for (int index = 0; index < num_of_interfaces; index++) {
        if (cfg_get_hostap_iface(index, ifname) == RETURN_ERR) {
            MAPF_ERR("failed to get wifi interface steer vaps for agent" << index);
        } else {
            if (std::string(ifname).length() > 0) {
                if (!load_steer_on_vaps_str.empty()) {
                    load_steer_on_vaps_str.append(",");
                }
                // for linux implementation the wlan?.0 vaps are used for band steering
                load_steer_on_vaps_str.append(std::string(ifname) + ".0");
            }
        }
    }
    if (load_steer_on_vaps_str.empty()) {
        MAPF_DBG("steer vaps list is empty");
        return RETURN_OK;
    }

    mapf::utils::copy_string(load_steer_on_vaps, load_steer_on_vaps_str.c_str(),
                             BPL_LOAD_STEER_ON_VAPS_LEN);

    return RETURN_OK;
}

int cfg_get_dcs_channel_pool(int radio_num, char channel_pool[BPL_DCS_CHANNEL_POOL_LEN])
{
    if (!channel_pool) {
        MAPF_ERR("invalid input: channel_pool is NULL");
        return RETURN_ERR;
    }

    if (radio_num < 0) {
        MAPF_ERR("invalid input: radio_num < 0");
        return RETURN_ERR;
    }

    mapf::utils::copy_string(channel_pool, DEFAULT_DCS_CHANNEL_POOL, BPL_DCS_CHANNEL_POOL_LEN);
    return RETURN_OK;
}

int cfg_get_stop_on_failure_attempts()
{
    int retVal = -1;
    if (cfg_get_param_int("stop_on_failure_attempts", retVal) == RETURN_ERR) {
        retVal = RETURN_ERR;
    }
    return retVal;
}

int cfg_is_onboarding() { return 0; }

int cfg_get_rdkb_extensions() { return 0; }

bool cfg_get_band_steering(bool &band_steering)
{
    int retVal = -1;
    if (cfg_get_param_int("band_steering", retVal) == RETURN_ERR) {
        return false;
    }

    band_steering = (retVal == 1);
    return true;
}

bool cfg_set_band_steering(bool band_steering) { return true; }

bool cfg_get_daisy_chaining_disabled(bool &daisy_chaining_disabled)
{
    int retVal = -1;
    if (cfg_get_param_int("daisy_chaining_disabled", retVal) == RETURN_ERR) {
        return false;
    }

    daisy_chaining_disabled = (retVal == 1);
    return true;
}

bool cfg_set_daisy_chaining_disabled(bool daisy_chaining_disabled) { return true; }

bool cfg_get_client_11k_roaming(bool &eleven_k_roaming)
{
    int retVal = -1;
    if (cfg_get_param_int("client_11k_roaming", retVal) == RETURN_ERR) {
        return false;
    }

    eleven_k_roaming = (retVal == 1);
    return true;
}

bool cfg_set_client_11k_roaming(bool eleven_k_roaming) { return true; }

bool cfg_get_client_roaming(bool &client_roaming)
{
    int retVal = -1;
    if (cfg_get_param_int("client_roaming", retVal) == RETURN_ERR) {
        return false;
    }

    client_roaming = (retVal == 1);
    return true;
}

bool cfg_set_client_roaming(bool client_roaming) { return true; }

bool cfg_get_load_balancing(bool &load_balancing)
{
    int retVal = -1;
    if (cfg_get_param_int("load_balancing", retVal) == RETURN_ERR) {
        return false;
    }

    load_balancing = (retVal == 1);
    return true;
}

bool cfg_set_load_balancing(bool load_balancing) { return true; }

bool cfg_get_channel_select_task(bool &channel_select_task_enabled)
{
    int retVal = -1;
    if (cfg_get_param_int("channel_select_task_enabled", retVal) == RETURN_ERR) {
        return false;
    }

    channel_select_task_enabled = (retVal == 1);
    return true;
}

bool cfg_set_channel_select_task(bool channel_select_task_enabled) { return true; }

bool cfg_get_dfs_reentry(bool &dfs_reentry_enabled)
{
    int retVal = -1;
    if (cfg_get_param_int("dfs_reentry", retVal) == RETURN_ERR) {
        return false;
    }

    dfs_reentry_enabled = (retVal == 1);
    return true;
}

bool cfg_set_dfs_reentry(bool dfs_reentry_enabled) { return true; }

bool cfg_get_dfs_task(bool &dfs_task_enabled)
{
    int retVal = -1;
    if (cfg_get_param_int("dfs_task_enabled", retVal) == RETURN_ERR) {
        return false;
    }

    dfs_task_enabled = (retVal == 1);
    return true;
}

bool cfg_set_dfs_task(bool dfs_task_enabled) { return true; }

bool cfg_get_health_check(bool &health_check_enabled)
{
    int retVal = -1;
    if (cfg_get_param_int("health_check_enabled", retVal) == RETURN_ERR) {
        return false;
    }

    health_check_enabled = (retVal == 1);
    return true;
}

bool cfg_set_health_check(bool health_check_enabled) { return true; }

bool cfg_get_ire_roaming(bool &ire_roaming)
{
    int retVal = -1;
    if (cfg_get_param_int("ire_roaming", retVal) == RETURN_ERR) {
        return false;
    }

    ire_roaming = (retVal == 1);
    return true;
}

bool cfg_set_ire_roaming(bool ire_roaming) { return true; }

bool cfg_get_optimal_path_prefer_signal_strenght(bool &optimal_path_prefer_signal_strenght)
{
    int retVal = -1;
    if (cfg_get_param_int("optimal_path_prefer_signal_strenght", retVal) == RETURN_ERR) {
        return false;
    }

    optimal_path_prefer_signal_strenght = (retVal == 1);
    return true;
}

bool cfg_set_optimal_path_prefer_signal_strenght(bool optimal_path_prefer_signal_strenght)
{
    return true;
}

bool cfg_get_diagnostics_measurements(bool &diagnostics_measurements)
{
    int retVal = -1;
    if (cfg_get_param_int("diagnostics_measurements", retVal) == RETURN_ERR) {
        return false;
    }

    diagnostics_measurements = (retVal == 1);
    return true;
}

bool cfg_set_diagnostics_measurements(bool diagnostics_measurements) { return true; }

bool cfg_get_diagnostics_measurements_polling_rate_sec(
    int &diagnostics_measurements_polling_rate_sec)
{
    int retVal = -1;
    if (cfg_get_param_int("diagnostics_measurements_polling_rate_sec", retVal) == RETURN_ERR) {
        MAPF_INFO("Failed to read diagnostics_measurements_polling_rate_sec parameter ");
        diagnostics_measurements_polling_rate_sec =
            DEFAULT_DIAGNOSTICS_MEASUREMENT_POLLING_RATE_SEC;
        return false;
    }

    diagnostics_measurements_polling_rate_sec = retVal;

    return true;
}

bool cfg_set_diagnostics_measurements_polling_rate_sec(
    const int &diagnostics_measurements_polling_rate_sec)
{
    return true;
}

int cfg_get_backhaul_params(int *max_vaps, int *network_enabled, int *preferred_radio_band)
{
    *max_vaps             = 0;
    *network_enabled      = 0;
    *preferred_radio_band = 0;
    return RETURN_OK;
}

int cfg_get_backhaul_vaps(char *backhaul_vaps_buf, const int buf_len)
{
    memset(backhaul_vaps_buf, 0, buf_len);
    return RETURN_OK;
}

int cfg_get_beerocks_credentials(const int radio_dir, char ssid[BPL_SSID_LEN],
                                 char pass[BPL_PASS_LEN], char sec[BPL_SEC_LEN])
{
    mapf::utils::copy_string(ssid, "test_beerocks_ssid", BPL_SSID_LEN);
    mapf::utils::copy_string(sec, "None", BPL_SEC_LEN);
    return RETURN_OK;
}

int cfg_get_security_policy() { return 0; }

int cfg_set_onboarding(int enable) { return RETURN_ERR; }

int cfg_notify_onboarding_completed(const char ssid[BPL_SSID_LEN], const char pass[BPL_PASS_LEN],
                                    const char sec[BPL_SEC_LEN],
                                    const char iface_name[BPL_IFNAME_LEN], const int success)
{
    return RETURN_ERR;
}

int cfg_notify_error(int code, const char data[BPL_ERROR_STRING_LEN]) { return RETURN_ERR; }

int cfg_get_administrator_credentials(char pass[BPL_PASS_LEN]) { return RETURN_ERR; }

bool cfg_get_zwdfs_flag(int &flag)
{
    if (cfg_get_param_int("zwdfs_flag", flag) < 0) {
        MAPF_DBG("Failed to read zwdfs_flag parameter - setting default value");
        flag = DEFAULT_ZWDFS_DISABLE;
    }

    return true;
}

bool cfg_get_best_channel_rank_threshold(uint32_t &threshold)
{
    int best_channel_rank_threshold;

    if (cfg_get_param_int("best_channel_rank_th", best_channel_rank_threshold) < 0) {
        MAPF_DBG("Failed to read best_channel_rank_th parameter - setting default value");
        best_channel_rank_threshold = DEFAULT_BEST_CHANNEL_RANKING_TH;
    }

    if (best_channel_rank_threshold < 0) {
        MAPF_ERR("best_channel_rank_th is configured to a negative value");
        return false;
    }

    threshold = best_channel_rank_threshold;

    return true;
}

bool cfg_get_persistent_db_enable(bool &enable)
{
    int persistent_db_enable = DEFAULT_PERSISTENT_DB;

    // persistent db value is optional
    if (cfg_get_param_int("persistent_db", persistent_db_enable) < 0) {
        MAPF_DBG("Failed to read persistent-db-enable parameter - setting default value");
        persistent_db_enable = DEFAULT_PERSISTENT_DB;
    }

    enable = (persistent_db_enable == 1);

    return true;
}

bool cfg_get_persistent_db_commit_changes_interval(unsigned int &interval_sec)
{
    int commit_changes_interval_value = beerocks::bpl::DEFAULT_COMMIT_CHANGES_INTERVAL_VALUE_SEC;

    // persistent db data commit interval value is optional
    if (cfg_get_param_int("persistent_db_commit_changes_interval_seconds",
                          commit_changes_interval_value) < 0) {
        MAPF_DBG("Failed to read commit_changes_interval parameter - setting default value");
        commit_changes_interval_value = beerocks::bpl::DEFAULT_COMMIT_CHANGES_INTERVAL_VALUE_SEC;
    }

    interval_sec = commit_changes_interval_value;

    return true;
}

bool cfg_get_clients_persistent_db_max_size(int &max_size)
{
    int max_size_val = -1;
    if (cfg_get_param_int("clients_persistent_db_max_size", max_size_val) == RETURN_ERR) {
        MAPF_ERR("Failed to read clients-persistent-db-max-size parameter - setting default value");
        max_size_val = DEFAULT_CLIENTS_PERSISTENT_DB_MAX_SIZE;
    }

    max_size = max_size_val;

    return true;
}

bool cfg_get_steer_history_persistent_db_max_size(size_t &max_size)
{
    int max_size_val = -1;

    if (cfg_get_param_int("steer_history_db_max_size", max_size_val) == RETURN_ERR) {
        MAPF_ERR("Failed to read steer-history-persistent-db-max-size parameter - setting default "
                 "value");
        max_size_val = DEFAULT_STEER_HISTORY_PERSISTENT_DB_MAX_SIZE;
    }
    max_size = max_size_val;
    return true;
}

bool cfg_get_max_timelife_delay_minutes(int &max_timelife_delay_minutes)
{
    int val = -1;
    if (cfg_get_param_int("max_timelife_delay_minutes", val) == RETURN_ERR) {
        MAPF_ERR("Failed to read max-timelife-delay-minutes parameter - setting default value");
        val = DEFAULT_MAX_TIMELIFE_DELAY_MINUTES;
    }

    max_timelife_delay_minutes = val;

    return true;
}

bool cfg_get_unfriendly_device_max_timelife_delay_minutes(
    int &unfriendly_device_max_timelife_delay_minutes)
{
    int val = -1;
    if (cfg_get_param_int("unfriendly_device_max_timelife_delay_minutes", val) == RETURN_ERR) {
        MAPF_ERR("Failed to read unfriendly-device-max-timelife-delay-minutes parameter - setting "
                 "default value");
        val = DEFAULT_MAX_TIMELIFE_DELAY_MINUTES;
    }

    unfriendly_device_max_timelife_delay_minutes = val;

    return true;
}

bool cfg_get_persistent_db_aging_interval(int &persistent_db_aging_interval_sec)
{
    int val = -1;
    if (cfg_get_param_int("persistent_db_aging_interval_sec", val) == RETURN_ERR) {
        MAPF_ERR("Failed to read persistent-db-aging-interval-sec parameter - setting "
                 "default value");
        val = DEFAULT_PERSISTENT_DB_AGING_INTERVAL_SEC;
    }

    persistent_db_aging_interval_sec = val;
    return true;
}

bool cfg_get_link_metrics_request_interval(std::chrono::seconds &link_metrics_request_interval_sec)
{
    int val = -1;
    if (cfg_get_param_int("link_metrics_request_interval_sec", val) == RETURN_ERR) {
        MAPF_INFO("Failed to read link_metrics_request_interval_sec parameter - setting "
                  "default value");
        link_metrics_request_interval_sec = DEFAULT_LINK_METRICS_REQUEST_INTERVAL_VALUE_SEC;
    } else {
        link_metrics_request_interval_sec = std::chrono::seconds{val};
    }

    return true;
}

bool cfg_set_link_metrics_request_interval(std::chrono::seconds &link_metrics_request_interval_sec)
{
    return true;
}

bool cfg_get_unsuccessful_assoc_report_policy(bool &unsuccessful_assoc_report_policy)
{
    int retVal = -1;
    if (cfg_get_param_int("unsuccessful_assoc_report_policy", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read unsuccessful_assoc_report_policy parameter - setting "
                 "default value");
        return false;
    }

    unsuccessful_assoc_report_policy = retVal;

    return true;
}

bool cfg_set_unsuccessful_assoc_report_policy(bool &unsuccessful_assoc_report_policy)
{
    return true;
}

bool cfg_get_unsuccessful_assoc_max_reporting_rate(
    unsigned int &unsuccessful_assoc_max_reporting_rate)
{
    int retVal = -1;
    if (cfg_get_param_int("unsuccessful_assoc_max_reporting_rate", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read unsuccessful_assoc_max_reporting_rate parameter - setting "
                 "default value");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("unsuccessful_assoc_max_reporting_rate is configured to a negative value");
        return false;
    }

    unsuccessful_assoc_max_reporting_rate = retVal;

    return true;
}

bool cfg_set_unsuccessful_assoc_max_reporting_rate(int &unsuccessful_assoc_max_reporting_rate)
{
    return true;
}

bool bpl_get_lan_interfaces(std::vector<std::string> &lan_iface_list)
{

    // TODO Default value is returned, add/set capability can be added in platform DB.
    lan_iface_list = beerocks::string_utils::str_split(DEFAULT_LINUX_LAN_INTERFACE_NAMES, ' ');
    return true;
}

bool bpl_cfg_get_backhaul_wire_iface(std::string &iface)
{
    std::string param = "backhaul_wire_iface";

    if (!cfg_get_param(param, iface)) {
        MAPF_ERR("Failed to read: " << param);
        return false;
    }

    return true;
}

bool cfg_get_roaming_hysteresis_percent_bonus(int &roaming_hysteresis_percent_bonus)
{
    int val = -1;
    if (cfg_get_param_int("roaming_hysteresis_percent_bonus", val) == RETURN_ERR) {
        return false;
    }

    roaming_hysteresis_percent_bonus = val;
    return true;
}

bool cfg_set_roaming_hysteresis_percent_bonus(int roaming_hysteresis_percent_bonus) { return true; }

bool cfg_get_steering_disassoc_timer_msec(std::chrono::milliseconds &steering_disassoc_timer_msec)
{
    int val = -1;
    if (cfg_get_param_int("steering_disassoc_timer_msec", val) == RETURN_ERR) {
        return false;
    }

    steering_disassoc_timer_msec = std::chrono::milliseconds{val};
    return true;
}

bool cfg_set_steering_disassoc_timer_msec(std::chrono::milliseconds &steering_disassoc_timer_msec)
{
    return true;
}

bool cfg_get_clients_measurement_mode(eClientsMeasurementMode &clients_measurement_mode)
{
    // Measure all clients
    clients_measurement_mode = eClientsMeasurementMode::ENABLE_ALL;

    return true;
}

bool cfg_get_radio_stats_enable(bool &radio_stats_enable)
{
    radio_stats_enable = true;

    return true;
}

bool cfg_get_rssi_measurements_timeout(int &rssi_measurements_timeout_msec)
{
    int retVal = DEFAULT_RSSI_MEASUREMENT_TIMEOUT_MSEC;

    // persistent db value is optional
    if (cfg_get_param_int("rssi_measurements_timeout", retVal) < 0) {
        MAPF_DBG("Failed to read rssi_measurements_timeout parameter - setting default value");
        retVal = DEFAULT_RSSI_MEASUREMENT_TIMEOUT_MSEC;
    }

    rssi_measurements_timeout_msec = retVal;

    return true;
}

bool cfg_get_beacon_measurements_timeout(int &beacon_measurements_timeout_msec)
{
    int retVal = DEFAULT_BEACON_MEASUREMENT_TIMEOUT_MSEC;

    // persistent db value is optional
    if (cfg_get_param_int("beacon_measurements_timeout", retVal) < 0) {
        MAPF_DBG("Failed to read beacon_measurements_timeout parameter - setting default value");
        retVal = DEFAULT_BEACON_MEASUREMENT_TIMEOUT_MSEC;
    }

    beacon_measurements_timeout_msec = retVal;

    return true;
}

bool cfg_get_sta_reporting_rcpi_threshold(unsigned int &sta_reporting_rcpi_threshold)
{
    int retVal = -1;
    if (cfg_get_param_int("sta_reporting_rcpi_threshold", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read sta_reporting_rcpi_threshold parameter - setting default value");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("sta_reporting_rcpi_threshold is configured to a negative value");
        return false;
    }

    sta_reporting_rcpi_threshold = retVal;

    return true;
}

bool cfg_get_sta_reporting_rcpi_hyst_margin_override_threshold(
    unsigned int &sta_reporting_rcpi_hyst_margin_override_threshold)
{
    int retVal = -1;
    if (cfg_get_param_int("sta_reporting_rcpi_hysteresis_margin_override_threshold", retVal) ==
        RETURN_ERR) {
        MAPF_DBG("Failed to read sta_reporting_rcpi_hysteresis_margin_override_threshold parameter "
                 "- setting default value");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("sta_reporting_rcpi_hysteresis_margin_override_threshold is configured to a "
                 "negative value");
        return false;
    }

    sta_reporting_rcpi_hyst_margin_override_threshold = retVal;

    return true;
}

bool cfg_get_ap_reporting_channel_utilization_threshold(
    unsigned int &ap_reporting_channel_utilization_threshold)
{
    int retVal = -1;
    if (cfg_get_param_int("ap_reporting_channel_utilization_threshold", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read ap_reporting_channel_utilization_threshold parameter - setting "
                 "default value");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("ap_reporting_channel_utilization_threshold is configured to a negative value");
        return false;
    }

    ap_reporting_channel_utilization_threshold = retVal;

    return true;
}

bool cfg_get_assoc_sta_traffic_stats_inclusion_policy(
    bool &assoc_sta_traffic_stats_inclusion_policy)
{
    int retVal = -1;
    if (cfg_get_param_int("assoc_sta_traffic_stats_inclusion_policy", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read assoc_sta_traffic_stats_inclusion_policy parameter - setting "
                 "default value");
        return false;
    }

    assoc_sta_traffic_stats_inclusion_policy = retVal > 0;

    return true;
}

bool cfg_get_assoc_sta_link_metrics_inclusion_policy(bool &assoc_sta_link_metrics_inclusion_policy)
{
    int retVal = -1;
    if (cfg_get_param_int("assoc_sta_link_metrics_inclusion_policy", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read assoc_sta_link_metrics_inclusion_policy parameter - setting "
                 "default value");
        return false;
    }

    assoc_sta_link_metrics_inclusion_policy = retVal > 0;

    return true;
}

bool cfg_get_assoc_wifi6_sta_status_report_inclusion_policy(
    bool &assoc_wifi6_sta_status_report_inclusion_policy)
{
    int retVal = -1;
    if (cfg_get_param_int("assoc_wifi6_sta_status_report_inclusion_policy", retVal) == RETURN_ERR) {
        MAPF_DBG(
            "Failed to read assoc_wifi6_sta_status_report_inclusion_policy parameter - setting "
            "default value");
        return false;
    }

    assoc_wifi6_sta_status_report_inclusion_policy = retVal > 0;

    return true;
}

bool cfg_get_steering_policy(unsigned int &steering_policy)
{
    int retVal = -1;
    if (cfg_get_param_int("steering_policy", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read steering_policy parameter - setting default value");
        return false;
    }

    steering_policy = retVal;

    return true;
}

bool cfg_get_channel_utilization_threshold(unsigned int &channel_utilization_threshold)
{
    int retVal = -1;
    if (cfg_get_param_int("channel_utilization_threshold", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read channel_utilization_threshold parameter - setting default value");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("channel_utilization_threshold is configured to a negative value");
        return false;
    }

    channel_utilization_threshold = retVal;

    return true;
}

bool cfg_get_rcpi_steering_threshold(unsigned int &rcpi_steering_threshold)
{
    int retVal = -1;
    if (cfg_get_param_int("rcpi_steering_threshold", retVal) == RETURN_ERR) {
        MAPF_DBG("Failed to read rcpi_steering_threshold parameter - setting default value");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("rcpi_steering_threshold is configured to a negative value");
        return false;
    }

    rcpi_steering_threshold = retVal;

    return true;
}

bool get_check_connectivity_to_controller_enable(bool &check_connectivity_enable)
{
    check_connectivity_enable = DEFAULT_CHECK_CONNECTIVITY_TO_CONTROLLER_ENABLE;
    return true;
}

bool get_check_indirect_connectivity_to_controller_enable(bool &check_indirect_connectivity_enable)
{
    check_indirect_connectivity_enable = DEFAULT_CHECK_INDIRECT_CONNECTIVITY_TO_CONTROLLER_ENABLE;
    return true;
}

bool get_controller_discovery_timeout_seconds(std::chrono::seconds &timeout_seconds)
{
    timeout_seconds = std::chrono::seconds{DEFAULT_CONTROLLER_DISCOVERY_TIMEOUT_SEC};
    return true;
}

bool get_controller_message_timeout_seconds(std::chrono::seconds &timeout_seconds)
{
    timeout_seconds = std::chrono::seconds{DEFAULT_CONTROLLER_MESSAGE_TIMEOUT_SEC};
    return true;
}

bool get_controller_heartbeat_state_timeout_seconds(std::chrono::seconds &timeout_seconds)
{
    timeout_seconds = std::chrono::seconds{DEFAULT_CONTROLLER_HEARTBEAT_STATE_TIMEOUT_SEC};
    return true;
}

bool cfg_get_clients_unicast_measurements(bool &clients_unicast_measurements)
{
    clients_unicast_measurements = false;
    return true;
}

bool cfg_commit_changes() { return true; };

} // namespace bpl
} // namespace beerocks
