/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl/bpl_cfg.h>

#include "../../common/uci/bpl_uci.h"
#include "../../common/utils/utils.h"
#include "../../common/utils/utils_net.h"

#include "bpl_cfg_helper.h"
#include "bpl_cfg_uci.h"

#include <bcl/beerocks_string_utils.h>
#include <mapf/common/logger.h>
#include <mapf/common/utils.h>

using namespace mapf;

namespace beerocks {
namespace bpl {

int cfg_get_hostap_iface_steer_vaps(int32_t radio_num,
                                    char hostap_iface_steer_vaps[BPL_LOAD_STEER_ON_VAPS_LEN])
{
    if (!hostap_iface_steer_vaps) {
        MAPF_ERR("invalid input: hostap_iface_steer_vaps is NULL");
        return RETURN_ERR;
    }

    if (radio_num < 0) {
        MAPF_ERR("invalid input: radio_num < 0");
        return RETURN_ERR;
    }

    return cfg_get_prplmesh_radio_param(radio_num, "hostap_iface_steer_vaps",
                                        hostap_iface_steer_vaps, BPL_LOAD_STEER_ON_VAPS_LEN);
}

int cfg_is_enabled()
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("enable", &retVal) == RETURN_ERR) {
        MAPF_ERR("cfg_is_enabled: Failed to read Enable parameter\n");
        return RETURN_ERR;
    }
    return retVal;
}

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
        return -1;
    }
}

int cfg_get_management_mode()
{
    int retVal                                = 0;
    char mgmt_mode[BPL_GW_DB_MANAGE_MODE_LEN] = {0};
    if (cfg_get_prplmesh_param("management_mode", mgmt_mode, BPL_GW_DB_MANAGE_MODE_LEN) < 0) {
        MAPF_ERR("cfg_get_management_mode: Failed to read management_mode");
        retVal = -1;
    } else {
        std::string mode_str(mgmt_mode);
        if (mode_str == "Multi-AP-Controller-and-Agent") {
            retVal = BPL_MGMT_MODE_MULTIAP_CONTROLLER_AGENT;
        } else if (mode_str == "Multi-AP-Controller") {
            retVal = BPL_MGMT_MODE_MULTIAP_CONTROLLER;
        } else if (mode_str == "Multi-AP-Agent") {
            retVal = BPL_MGMT_MODE_MULTIAP_AGENT;
        } else if (mode_str == "Not-Multi-AP") {
            retVal = BPL_MGMT_MODE_NOT_MULTIAP;
        } else {
            MAPF_ERR("cfg_get_management_mode: Unexpected management_mode");
            retVal = -1;
        }
    }
    return retVal;
}

int cfg_get_operating_mode()
{
    int retVal                            = 0;
    char op_mode[BPL_GW_DB_OPER_MODE_LEN] = {0};
    if (cfg_get_prplmesh_param("operating_mode", op_mode, BPL_GW_DB_OPER_MODE_LEN) < 0) {
        MAPF_ERR("cfg_get_operating_mode: Failed to read OperatingMode\n");
        retVal = -1;
    } else {
        std::string mode_str(op_mode);
        if (mode_str == "Gateway") {
            retVal = BPL_OPER_MODE_GATEWAY;
        } else if (mode_str == "Gateway-WISP") {
            retVal = BPL_OPER_MODE_GATEWAY_WISP;
        } else if (mode_str == "WDS-Extender") {
            retVal = BPL_OPER_MODE_WDS_EXTENDER;
        } else if (mode_str == "WDS-Repeater") {
            retVal = BPL_OPER_MODE_WDS_REPEATER;
        } else if (mode_str == "L2NAT-Client") {
            retVal = BPL_OPER_MODE_L2NAT_CLIENT;
        } else {
            MAPF_ERR("cfg_get_operating_mode: Unexpected OperatingMode\n");
            retVal = -1;
        }
    }
    return retVal;
}

int cfg_get_certification_mode()
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("certification_mode", &retVal) == RETURN_ERR) {
        MAPF_ERR("cfg_get_certification_mode: Failed to read certification_mode parameter\n");
        return RETURN_ERR;
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
    char hostap_iface_steer_vaps[BPL_LOAD_STEER_ON_VAPS_LEN] = {0};
    for (int index = 0; index < num_of_interfaces; index++) {
        if (cfg_get_hostap_iface_steer_vaps(index, hostap_iface_steer_vaps) == RETURN_OK) {
            if (std::string(hostap_iface_steer_vaps).length() > 0) {
                if (!load_steer_on_vaps_str.empty()) {
                    load_steer_on_vaps_str.append(",");
                }
                load_steer_on_vaps_str.append(std::string(hostap_iface_steer_vaps));
                MAPF_DBG("adding interface " << hostap_iface_steer_vaps
                                             << " to the steer on vaps list");
            }
        }
    }

    if (load_steer_on_vaps_str.empty()) {
        MAPF_DBG("steer on vaps list is not configured");
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

    return cfg_get_prplmesh_radio_param(radio_num, "dcs_channel_pool", channel_pool,
                                        BPL_DCS_CHANNEL_POOL_LEN);
}

int cfg_get_stop_on_failure_attempts()
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("stop_on_failure_attempts", &retVal,
                                           DEFAULT_STOP_ON_FAILURE_ATTEMPTS) == RETURN_ERR) {

        MAPF_INFO("cfg_get_stop_on_failure_attempts: Failed to read stop_on_failure_attempts "
                  "parameter\n");
        return RETURN_ERR;
    }
    return retVal;
}

int cfg_is_onboarding()
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("onboarding", &retVal) == RETURN_ERR) {
        MAPF_ERR("cfg_is_onboarding: Failed to read Onboarding parameter\n");
        return RETURN_ERR;
    }
    return retVal;
}

int cfg_get_rdkb_extensions()
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("rdkb_extensions", &retVal, DEFAULT_RDKB_EXTENSIONS) ==
        RETURN_ERR) {
        MAPF_INFO("cfg_get_rdkb_extensions: Failed to read RDKB Extensions parameter\n");
        return RETURN_ERR;
    }
    return retVal;
}

bool cfg_get_band_steering(bool &band_steering)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("band_steering", &retVal) == RETURN_ERR) {
        return false;
    }

    band_steering = (retVal == 1);
    return true;
}

bool cfg_set_band_steering(bool band_steering)
{
    std::string option = "band_steering";
    std::string value  = std::to_string(((int)band_steering));

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_client_11k_roaming(bool &eleven_k_roaming)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("client_11k_roaming", &retVal) == RETURN_ERR) {
        return false;
    }

    eleven_k_roaming = (retVal == 1);
    return true;
}

bool cfg_set_client_11k_roaming(bool eleven_k_roaming)
{
    std::string option = "client_11k_roaming";
    std::string value  = std::to_string(((int)eleven_k_roaming));

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_client_roaming(bool &client_roaming)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("client_roaming", &retVal) == RETURN_ERR) {
        return false;
    }

    client_roaming = (retVal == 1);
    return true;
}

bool cfg_set_client_roaming(bool client_roaming)
{
    std::string option = "client_roaming";
    std::string value  = std::to_string(((int)client_roaming));

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_load_balancing(bool &load_balancing)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("load_balancing", &retVal) == RETURN_ERR) {
        return false;
    }

    load_balancing = (retVal == 1);
    return true;
}

bool cfg_set_load_balancing(bool load_balancing)
{
    std::string option = "load_balancing";
    std::string value  = std::to_string(((int)load_balancing));

    return cfg_set_prplmesh_config(option, value);
}


bool cfg_get_dfs_reentry(bool &dfs_reentry_enabled)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("dfs_reentry", &retVal) == RETURN_ERR) {
        return false;
    }

    dfs_reentry_enabled = (retVal == 1);
    return true;
}

bool cfg_set_dfs_reentry(bool dfs_reentry_enabled)
{
    std::string option = "dfs_reentry";
    std::string value  = std::to_string(((int)dfs_reentry_enabled));

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_ire_roaming(bool &ire_roaming)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("ire_roaming", &retVal) == RETURN_ERR) {
        return false;
    }

    ire_roaming = (retVal == 1);
    return true;
}

bool cfg_set_ire_roaming(bool ire_roaming)
{
    std::string option = "ire_roaming";
    std::string value  = std::to_string(((int)ire_roaming));

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_optimal_path_prefer_signal_strenght(bool &optimal_path_prefer_signal_strenght)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("optimal_path_prefer_signal_strenght", &retVal) == RETURN_ERR) {
        return false;
    }

    optimal_path_prefer_signal_strenght = (retVal == 1);
    return true;
}

bool cfg_set_optimal_path_prefer_signal_strenght(bool optimal_path_prefer_signal_strenght)
{
    std::string option = "optimal_path_prefer_signal_strenght";
    std::string value  = std::to_string(((int)optimal_path_prefer_signal_strenght));

    return cfg_set_prplmesh_config(option, value);
}

int cfg_get_backhaul_params(int *max_vaps, int *network_enabled, int *preferred_radio_band)
{
    if (max_vaps) {
        //get max_vaps
    }

    if (network_enabled) {
        //get network_enabled
    }

    if (preferred_radio_band) {
        char backhaul_band[BPL_BACKHAUL_BAND_LEN] = {0};
        //get preferred_radio_band
        int retVal = cfg_get_prplmesh_param("backhaul_band", backhaul_band, BPL_BACKHAUL_BAND_LEN);
        if (retVal == RETURN_ERR) {
            MAPF_ERR("cfg_get_backhaul_params: Failed to read backhaul_band parameter\n");
            return RETURN_ERR;
        }
        std::string preferred_bh_band(backhaul_band);
        if (preferred_bh_band.compare("2.4GHz") == 0) {
            *preferred_radio_band = BPL_RADIO_BAND_2G;
        } else if (preferred_bh_band.compare("5GHz") == 0) {
            *preferred_radio_band = BPL_RADIO_BAND_5G;
        } else if (preferred_bh_band.compare("6GHz") == 0) {
            *preferred_radio_band = BPL_RADIO_BAND_6G;
        } else if (preferred_bh_band.compare("auto") == 0) {
            *preferred_radio_band = BPL_RADIO_BAND_AUTO;
        } else {
            MAPF_ERR("cfg_get_backhaul_params: unknown backhaul_band parameter value\n");
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

int cfg_get_backhaul_vaps(char *backhaul_vaps_buf, const int buf_len) { return 0; }

int cfg_get_beerocks_credentials(const int radio_dir, char ssid[BPL_SSID_LEN],
                                 char pass[BPL_PASS_LEN], char sec[BPL_SEC_LEN])
{
    int retVal = 0;

    retVal |= cfg_get_prplmesh_param("ssid", ssid, BPL_SSID_LEN);
    retVal |= cfg_get_prplmesh_param("mode_enabled", sec, BPL_SEC_LEN);
    if (!strcmp(sec, "WEP-64") || !strcmp(sec, "WEP-128")) {
        retVal |= cfg_get_prplmesh_param("wep_key", pass, BPL_PASS_LEN);
    } else {
        retVal |= cfg_get_prplmesh_param("key_passphrase", pass, BPL_PASS_LEN);
    }

    return retVal;
}

int cfg_get_security_policy()
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("mem_only_psk", &retVal) == RETURN_ERR) {
        MAPF_ERR("cfg_get_security_policy: Failed to read mem_only_psk parameter\n");
        return RETURN_ERR;
    }
    return retVal;
}

int cfg_notify_onboarding_completed(const char ssid[BPL_SSID_LEN], const char pass[BPL_PASS_LEN],
                                    const char sec[BPL_SEC_LEN],
                                    const char iface_name[BPL_IFNAME_LEN], const int success)
{
    //return (sl_beerocks_notify_onboarding_completed(ssid, pass, sec, iface_name, success) ? 0 : -1);
    return 0;
}

int cfg_notify_error(int code, const char data[BPL_ERROR_STRING_LEN]) { return 0; }

int cfg_get_administrator_credentials(char pass[BPL_PASS_LEN]) { return 0; }

bool cfg_get_zwdfs_flag(int &flag)
{
    if (cfg_get_prplmesh_param_int_default("zwdfs_flag", &flag, DEFAULT_ZWDFS_DISABLE) ==
        RETURN_ERR) {
        MAPF_ERR("Failed to read zwdfs_flag parameter");
        return false;
    }

    return true;
}

bool cfg_get_best_channel_rank_threshold(uint32_t &threshold)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("best_channel_rank_th", &retVal,
                                           DEFAULT_BEST_CHANNEL_RANKING_TH) == RETURN_ERR) {
        MAPF_ERR("Failed to read best_channel_rank_th parameter");
        return false;
    }

    if (retVal < 0) {
        MAPF_ERR("best_channel_rank_th is configured to a negative value");
        return false;
    }

    threshold = retVal;

    return true;
}

bool cfg_get_persistent_db_enable(bool &enable)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("persistent_db", &retVal, DEFAULT_PERSISTENT_DB) ==
        RETURN_ERR) {
        MAPF_ERR("Failed to read persistent-db-enable parameter");
        return false;
    }

    enable = (retVal == 1);

    return true;
}

bool cfg_get_persistent_db_commit_changes_interval(unsigned int &interval_sec)
{
    int commit_changes_value = DEFAULT_COMMIT_CHANGES_INTERVAL_VALUE_SEC;

    if (cfg_get_prplmesh_param_int_default("commit_changes_interval", &commit_changes_value,
                                           DEFAULT_COMMIT_CHANGES_INTERVAL_VALUE_SEC) ==
        RETURN_ERR) {
        MAPF_ERR("Failed to read commit_changes_interval parameter");
        return false;
    }

    interval_sec = commit_changes_value;

    return true;
}

bool cfg_get_clients_persistent_db_max_size(int &max_size)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("clients_persistent_db_max_size", &retVal,
                                           DEFAULT_CLIENTS_PERSISTENT_DB_MAX_SIZE) == RETURN_ERR) {
        MAPF_ERR("Failed to read clients-persistent-db-max-size parameter");
        return false;
    }

    max_size = retVal;

    return true;
}

bool cfg_get_steer_history_persistent_db_max_size(size_t &max_size)
{
    int retVal = -1;

    if (cfg_get_prplmesh_param_int_default("steer_history_db_max_size", &retVal,
                                           DEFAULT_STEER_HISTORY_PERSISTENT_DB_MAX_SIZE) ==
        RETURN_ERR) {
        MAPF_ERR("Failed to read steer-history-persistent-db-max-size parameter");
        return false;
    }
    max_size = retVal;
    return true;
}

bool cfg_get_max_timelife_delay_minutes(int &max_timelife_delay_minutes)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("max_timelife_delay_minutes", &retVal,
                                           DEFAULT_MAX_TIMELIFE_DELAY_MINUTES) == RETURN_ERR) {
        MAPF_ERR("Failed to read max-timelife-delay-minutes parameter");
        return false;
    }

    max_timelife_delay_minutes = retVal;

    return true;
}

bool cfg_get_unfriendly_device_max_timelife_delay_minutes(
    int &unfriendly_device_max_timelife_delay_minutes)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("unfriendly_device_max_timelife_delay_minutes", &retVal,
                                           DEFAULT_UNFRIENDLY_DEVICE_MAX_TIMELIFE_DELAY_MINUTES) ==
        RETURN_ERR) {
        MAPF_ERR("Failed to read unfriendly-device-max-timelife-delay-minutes parameter");
        return false;
    }

    unfriendly_device_max_timelife_delay_minutes = retVal;

    return true;
}

bool cfg_get_persistent_db_aging_interval(int &persistent_db_aging_interval_sec)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("persistent_db_aging_interval_sec", &retVal,
                                           DEFAULT_PERSISTENT_DB_AGING_INTERVAL_SEC) ==
        RETURN_ERR) {
        MAPF_ERR("Failed to read persistent-db-aging-interval-sec parameter - setting "
                 "default value");
        return false;
    }

    persistent_db_aging_interval_sec = retVal;

    return true;
}

bool cfg_get_link_metrics_request_interval(std::chrono::seconds &link_metrics_request_interval_sec)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default(
            "link_metrics_request_interval_sec", &retVal,
            DEFAULT_LINK_METRICS_REQUEST_INTERVAL_VALUE_SEC.count()) == RETURN_ERR) {
        MAPF_INFO("Failed to read link_metrics_request_interval_sec parameter - setting "
                  "default value");
        return false;
    }

    link_metrics_request_interval_sec = std::chrono::seconds{retVal};
    return true;
}

bool cfg_set_link_metrics_request_interval(std::chrono::seconds &link_metrics_request_interval_sec)
{
    std::string option = "link_metrics_request_interval_sec";
    std::string value  = std::to_string(link_metrics_request_interval_sec.count());

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_unsuccessful_assoc_report_policy(bool &unsuccessful_assoc_report_policy)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("unsuccessful_assoc_report_policy", &retVal,
                                           DEFAULT_UNSUCCESSFUL_ASSOC_REPORT_POLICY) ==
        RETURN_ERR) {
        MAPF_INFO("Failed to read unsuccessful_assoc_report_policy parameter - setting "
                  "default value");
        return false;
    }

    unsuccessful_assoc_report_policy = (retVal == 1);
    LOG(DEBUG) << "get unsuccessful_assoc_report_policy: " << unsuccessful_assoc_report_policy;
    return true;
}

bool cfg_set_unsuccessful_assoc_report_policy(bool &unsuccessful_assoc_report_policy)
{
    std::string option = "unsuccessful_assoc_report_policy";
    std::string value  = std::to_string((int)unsuccessful_assoc_report_policy);
    LOG(DEBUG) << "set unsuccessful_assoc_report_policy: " << value;
    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_unsuccessful_assoc_max_reporting_rate(int &unsuccessful_assoc_max_reporting_rate)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("unsuccessful_assoc_max_reporting_rate", &retVal,
                                           DEFAULT_UNSUCCESSFUL_ASSOC_MAX_REPORTING_RATE) ==
        RETURN_ERR) {
        MAPF_INFO("Failed to read unsuccessful_assoc_max_reporting_rate parameter - setting "
                  "default value");
        return false;
    }

    unsuccessful_assoc_max_reporting_rate = retVal;

    return true;
}

bool cfg_set_unsuccessful_assoc_max_reporting_rate(int &unsuccessful_assoc_max_reporting_rate)
{
    std::string option = "unsuccessful_assoc_max_reporting_rate";
    std::string value  = std::to_string(unsuccessful_assoc_max_reporting_rate);

    return cfg_set_prplmesh_config(option, value);
}

bool bpl_get_lan_interfaces(std::vector<std::string> &lan_iface_list)
{
    std::string iface_names;
    if (cfg_uci_get_lan_interfaces("lan", iface_names) != RETURN_OK) {
        LOG(ERROR) << "Read network lan interfaces names from UCI failed.";
    }

    lan_iface_list = beerocks::string_utils::str_split(iface_names, ' ');
    return true;
}

bool bpl_cfg_get_backhaul_wire_iface(std::string &iface)
{
    char ifname[BPL_IFNAME_LEN + 1] = {0};

    int retVal = cfg_get_prplmesh_param("backhaul_wire_iface", ifname, BPL_IFNAME_LEN);
    if (retVal == RETURN_ERR) {
        MAPF_ERR("bpl_cfg_get_backhaul_wire_iface: Failed to read backhaul_wire_iface parameter\n");
        return false;
    }

    iface = ifname;

    return true;
}

bool cfg_get_roaming_hysteresis_percent_bonus(int &roaming_hysteresis_percent_bonus)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("roaming_hysteresis_percent_bonus", &retVal) == RETURN_ERR) {
        return false;
    }

    roaming_hysteresis_percent_bonus = retVal;
    return true;
}

bool cfg_set_roaming_hysteresis_percent_bonus(int roaming_hysteresis_percent_bonus)
{
    std::string option = "roaming_hysteresis_percent_bonus";
    std::string value  = std::to_string(roaming_hysteresis_percent_bonus);

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_steering_disassoc_timer_msec(std::chrono::milliseconds &steering_disassoc_timer_msec)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int("steering_disassoc_timer_msec", &retVal) == RETURN_ERR) {
        return false;
    }

    steering_disassoc_timer_msec = std::chrono::milliseconds{retVal};
    return true;
}

bool cfg_set_steering_disassoc_timer_msec(std::chrono::milliseconds &steering_disassoc_timer_msec)
{
    std::string option = "steering_disassoc_timer_msec";
    std::string value  = std::to_string(steering_disassoc_timer_msec.count());

    return cfg_set_prplmesh_config(option, value);
}

bool cfg_get_clients_measurement_mode(eClientsMeasurementMode &clients_measurement_mode)
{
    int val = -1;
    if (cfg_get_prplmesh_param_int_default("clients_measurement_mode", &val,
                                           int(eClientsMeasurementMode::ENABLE_ALL)) ==
        RETURN_ERR) {
        clients_measurement_mode = eClientsMeasurementMode::ENABLE_ALL;
        LOG(ERROR) << "Failed to read clients_measurement_mode parameter, "
                      "default value: ENABLE_ALL";
        return false;
    }

    if (val > int(eClientsMeasurementMode::ONLY_CLIENTS_SELECTED_FOR_STEERING)) {
        LOG(WARNING) << "clients_measurement_mode is set to invalid value - setting "
                        "default value: ENABLE_ALL";
        clients_measurement_mode = eClientsMeasurementMode::ENABLE_ALL;
    } else {
        clients_measurement_mode = eClientsMeasurementMode(val);
    }

    return true;
}

bool cfg_get_radio_stats_enable(bool &radio_stats_enable)
{
    int val = -1;
    if (cfg_get_prplmesh_param_int_default("radio_stats_enable", &val, int(true)) == RETURN_ERR) {
        LOG(ERROR) << "Failed to read radio_stats_enable parameter, setting default value true";
        radio_stats_enable = true;
        return false;
    }

    radio_stats_enable = bool(val == 1);
    return true;
}

bool cfg_get_rssi_measurements_timeout(int &rssi_measurements_timeout_msec)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("rssi_measurements_timeout", &retVal,
                                           DEFAULT_RSSI_MEASUREMENT_TIMEOUT_MSEC) == RETURN_ERR) {
        MAPF_ERR("Failed to read rssi_measurements_timeout parameter");
        return false;
    }

    rssi_measurements_timeout_msec = retVal;

    return true;
}

bool cfg_get_beacon_measurements_timeout(int &beacon_measurements_timeout_msec)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("beacon_measurements_timeout", &retVal,
                                           DEFAULT_BEACON_MEASUREMENT_TIMEOUT_MSEC) == RETURN_ERR) {
        MAPF_ERR("Failed to read beacon_measurements_timeout parameter");
        return false;
    }

    beacon_measurements_timeout_msec = retVal;

    return true;
}

bool get_check_connectivity_to_controller_enable(bool &check_connectivity_enable)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("check_connectivity_to_controller_enable", &retVal,
                                           DEFAULT_CHECK_CONNECTIVITY_TO_CONTROLLER_ENABLE) ==
        RETURN_ERR) {
        MAPF_INFO("Failed to read check_connectivity_to_controller_enable parameter");
        return false;
    }

    check_connectivity_enable = (retVal == 1);
    return true;
}

bool get_check_indirect_connectivity_to_controller_enable(bool &check_indirect_connectivity_enable)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default(
            "check_indirect_connectivity_to_controller_enable", &retVal,
            DEFAULT_CHECK_INDIRECT_CONNECTIVITY_TO_CONTROLLER_ENABLE) == RETURN_ERR) {
        MAPF_INFO("Failed to read check_indirect_connectivity_to_controller_enable parameter");
        return false;
    }

    check_indirect_connectivity_enable = (retVal == 1);
    return true;
}

bool get_controller_discovery_timeout_seconds(std::chrono::seconds &timeout_seconds)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("controller_discovery_timeout_seconds", &retVal,
                                           DEFAULT_CONTROLLER_DISCOVERY_TIMEOUT_SEC.count()) ==
        RETURN_ERR) {
        MAPF_INFO("Failed to read controller_discovery_timeout_seconds parameter - setting "
                  "default value");
        return false;
    }

    timeout_seconds = std::chrono::seconds{retVal};
    return true;
}

bool get_controller_message_timeout_seconds(std::chrono::seconds &timeout_seconds)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default("controller_message_timeout_seconds", &retVal,
                                           DEFAULT_CONTROLLER_MESSAGE_TIMEOUT_SEC.count()) ==
        RETURN_ERR) {
        MAPF_INFO("Failed to read controller_message_timeout_seconds parameter - setting "
                  "default value");
        return false;
    }

    timeout_seconds = std::chrono::seconds{retVal};
    return true;
}

bool get_controller_heartbeat_state_timeout_seconds(std::chrono::seconds &timeout_seconds)
{
    int retVal = -1;
    if (cfg_get_prplmesh_param_int_default(
            "controller_heartbeat_state_timeout_seconds", &retVal,
            DEFAULT_CONTROLLER_HEARTBEAT_STATE_TIMEOUT_SEC.count()) == RETURN_ERR) {
        MAPF_INFO("Failed to read controller_heartbeat_state_timeout_seconds parameter - setting "
                  "default value");
        return false;
    }

    timeout_seconds = std::chrono::seconds{retVal};
    return true;
}

} // namespace bpl
} // namespace beerocks
