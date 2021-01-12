/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "on_action.h"

using namespace beerocks;
using namespace net;
using namespace son;
namespace prplmesh {
namespace controller {
namespace actions {

// Actions

son::db *g_database = nullptr;

static amxd_status_t action_read_last_change(amxd_object_t *object, amxd_param_t *param,
                                             amxd_action_t reason, const amxc_var_t *const args,
                                             amxc_var_t *const retval, void *priv)
{
    /*
        This action retrieves CreationTime of BSS instance from BSS.LastChange parameter,
        since BSS.Enabled changes just once when we create BSS instance BSS.LastChange is constant.
        Than we retrieve CurrentTime and subtract CreationTime for getting time passed
        from creation in seconds.
    */
    if (reason != action_param_read) {
        LOG(ERROR) << "Failed to get data, incorrect reason: " << reason;
        return amxd_status_function_not_implemented;
    }
    if (!param) {
        return amxd_status_parameter_not_found;
    }

    auto status = amxd_action_param_read(object, param, reason, args, retval, priv);
    if (status != amxd_status_ok) {
        return status;
    }
    auto creation_time = amxc_var_dyncast(uint64_t, retval);

    auto current_time = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();

    uint32_t last_change = current_time - creation_time;

    amxc_var_set(uint32_t, retval, last_change);

    return amxd_status_ok;
}

/**
 * @brief Overwrite action 'read' aka 'get', that it will display an empty
 * string insted of real value when action is applied.
 */
static amxd_status_t display_empty_val(amxd_object_t *object, amxd_param_t *param,
                                       amxd_action_t reason, const amxc_var_t *const args,
                                       amxc_var_t *const retval, void *priv)
{
    if (reason != action_param_read) {
        return amxd_status_function_not_implemented;
    }
    if (!param) {
        return amxd_status_parameter_not_found;
    }

    // Read the value from the data model. We will not actually use the value, but
    // amxd_action_param_read does all necessary checks and prepares retval appropriately.
    auto status = amxd_action_param_read(object, param, reason, args, retval, priv);
    amxc_var_set(cstring_t, retval, "");
    return status;
}

static std::string get_param_string(amxd_object_t *object, const char *param_name)
{
    amxc_var_t param;
    char *param_val = NULL;

    amxc_var_init(&param);
    if (amxd_object_get_param(object, param_name, &param) == amxd_status_ok) {
        param_val = amxc_var_dyncast(cstring_t, &param);
    } else {
        amxc_var_clean(&param);
        return {};
    }
    amxc_var_clean(&param);
    return param_val;
}

static bool get_param_bool(amxd_object_t *object, const char *param_name)
{
    amxc_var_t param;
    bool param_val = false;

    amxc_var_init(&param);
    if (amxd_object_get_param(object, param_name, &param) == amxd_status_ok) {
        param_val = amxc_var_constcast(bool, &param);
    } else {
        LOG(ERROR) << "Fail to get param: " << param_name;
    }
    amxc_var_clean(&param);
    return param_val;
}

/**
* @brief Overwrite an action 'get' aka 'read' for Controller.Network.AccessPointCommit
* data element, that when this element is triggered the bss information from 
* Controller.Network.AccessPoint and Controller.Network.AccessPoint.n.Security,
* where n = element's index, objects will be stored in the sAccessPoint structure.
*/
amxd_status_t access_point_commit(amxd_object_t *object, amxd_function_t *func, amxc_var_t *args,
                                  amxc_var_t *ret)
{
    amxc_var_clean(ret);
    amxd_object_t *access_point = amxd_object_get_child(object, "AccessPoint");

    if (!access_point) {
        LOG(WARNING) << "Fail to get AccessPoint object from data model";
        return amxd_status_ok;
    }

    g_database->clear_bss_info_configuration();
    amxd_object_for_each(instance, it, access_point)
    {
        son::wireless_utils::sBssInfoConf bss_info;
        amxd_object_t *access_point_inst = amxc_llist_it_get_data(it, amxd_object_t, it);
        amxd_object_t *security_inst     = amxd_object_get_child(access_point_inst, "Security");

        bss_info.ssid      = get_param_string(access_point_inst, "SSID");
        auto multi_ap_mode = get_param_string(access_point_inst, "MultiApMode");
        bss_info.backhaul  = (multi_ap_mode.find("Backhaul") != std::string::npos);
        bss_info.fronthaul = (multi_ap_mode.find("Fronthaul") != std::string::npos);

        if (!bss_info.backhaul && !bss_info.fronthaul) {
            LOG(DEBUG) << "MultiApMode for AccessPoint: " << bss_info.ssid << " is not set.";
            continue;
        }
        if (get_param_bool(access_point_inst, "Band2_4G")) {
            bss_info.operating_class.splice(bss_info.operating_class.end(),
                                            son::wireless_utils::string_to_wsc_oper_class("24g"));
        }
        if (get_param_bool(access_point_inst, "Band5GH")) {
            bss_info.operating_class.splice(bss_info.operating_class.end(),
                                            son::wireless_utils::string_to_wsc_oper_class("5gh"));
        }
        if (get_param_bool(access_point_inst, "Band5GL")) {
            bss_info.operating_class.splice(bss_info.operating_class.end(),
                                            son::wireless_utils::string_to_wsc_oper_class("5gl"));
        }
        if (get_param_bool(access_point_inst, "Band6G")) {
            bss_info.operating_class.splice(bss_info.operating_class.end(),
                                            son::wireless_utils::string_to_wsc_oper_class("6g"));
        }
        if (bss_info.operating_class.empty()) {
            LOG(DEBUG) << "Band for Access Point: " << bss_info.ssid << " is not set.";
            continue;
        }

        std::string mode_enabled = get_param_string(security_inst, "ModeEnabled");
        if (mode_enabled == "WPA3-Personal") {
            bss_info.network_key         = get_param_string(security_inst, "SAEPassphrase");
            bss_info.authentication_type = WSC::eWscAuth::WSC_AUTH_SAE;
            bss_info.encryption_type     = WSC::eWscEncr::WSC_ENCR_AES;
        } else if (mode_enabled == "WPA2-Personal") {
            bss_info.network_key = get_param_string(security_inst, "PreSharedKey");
            if (bss_info.network_key.empty()) {
                bss_info.network_key = get_param_string(security_inst, "KeyPassphrase");
            }
            bss_info.authentication_type = WSC::eWscAuth::WSC_AUTH_WPA2PSK;
            bss_info.encryption_type     = WSC::eWscEncr::WSC_ENCR_AES;
        } else {
            bss_info.authentication_type = WSC::eWscAuth::WSC_AUTH_OPEN;
            bss_info.encryption_type     = WSC::eWscEncr::WSC_ENCR_NONE;
        }
        LOG(DEBUG) << "Add bss info configration for AP with ssid: " << bss_info.ssid
                   << " and operating classes: " << bss_info.operating_class;
        g_database->add_bss_info_configuration(bss_info);
    }

    // Update wifi credentials
    uint8_t m_tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(m_tx_buffer, sizeof(m_tx_buffer));
    auto connected_ires = g_database->get_all_connected_ires();

    for (auto &hostap : connected_ires) {
        auto agent_mac = g_database->get_node_parent_ire(hostap);

        if (!son_actions::send_ap_config_renew_msg(cmdu_tx, *g_database,
                                                   tlvf::mac_from_string(agent_mac))) {
            LOG(ERROR) << "Failed son_actions::send_ap_config_renew_msg ! ";
        }
    }
    return amxd_status_ok;
}

// Events

amxd_dm_t *g_data_model = nullptr;

static void rm_params(amxd_object_t *object, const char *param_name)
{
    amxd_param_t *param = amxd_object_get_param_def(object, param_name);

    if (param) {
        amxd_action_param_destroy(object, param, action_param_destroy, NULL, NULL, NULL);
        amxd_param_delete(&param);
    }
}

static void add_string_param(const char *param_name, amxd_object_t *param_owner_obj)
{
    amxd_param_t *param = NULL;

    amxd_param_new(&param, param_name, AMXC_VAR_ID_CSTRING);
    amxd_object_add_param(param_owner_obj, param);
    amxd_param_add_action_cb(param, action_param_read, display_empty_val, NULL);
}

/**
 * @brief Removes PreSharedKey, KeyPassphrase, SAEPassphrase parameters 
 * from Controller.Network.AccessPoint.*.Security object.
 * event_rm_params() invokes when value of parameter
 * Controller.Network.AccessPoint.*.Security.ModeEnabled changed
 * from "WPA2-Personal" to any of other availeble values.
 */
static void event_rm_params(const char *const sig_name, const amxc_var_t *const data,
                            void *const priv)
{
    amxd_object_t *security_obj = amxd_dm_signal_get_object(g_data_model, data);

    if (!security_obj) {
        LOG(WARNING) << "Failed to get object Controller.Network.AccessPoint.*.Security";
        return;
    }
    rm_params(security_obj, "PreSharedKey");
    rm_params(security_obj, "KeyPassphrase");
    rm_params(security_obj, "SAEPassphrase");
}

/**
 * @brief Add PreSharedKey, KeyPassphrase, SAEPassphrase parameters 
 * to Controller.Network.AccessPoint.*.Security object.
 * Function invokes when value of parameter
 * Controller.Network.AccessPoint.*.Security.ModeEnabled changed to "WPA2-Personal".
 */
static void event_add_hidden_params(const char *const sig_name, const amxc_var_t *const data,
                                    void *const priv)
{
    amxd_object_t *security_obj = amxd_dm_signal_get_object(g_data_model, data);

    if (!security_obj) {
        LOG(WARNING) << "Failed to get object Controller.Network.AccessPoint.*.Security";
        return;
    }
    add_string_param("PreSharedKey", security_obj);
    add_string_param("KeyPassphrase", security_obj);
    add_string_param("SAEPassphrase", security_obj);
}

std::vector<beerocks::nbapi::sActionsCallback> get_actions_callback_list(void)
{
    const std::vector<beerocks::nbapi::sActionsCallback> actions_list = {
        {"action_read_last_change", action_read_last_change},
        {"display_empty_val", display_empty_val},
    };
    return actions_list;
}

std::vector<beerocks::nbapi::sEvents> get_events_list(void)
{
    const std::vector<beerocks::nbapi::sEvents> events_list = {
        {"event_rm_params", event_rm_params},
        {"event_add_hidden_params", event_add_hidden_params},
    };
    return events_list;
}

std::vector<beerocks::nbapi::sFunctions> get_func_list(void)
{
    const std::vector<beerocks::nbapi::sFunctions> functions_list = {
        {"access_point_commit", "Controller.Network.AccessPointCommit", access_point_commit},
    };
    return functions_list;
}

beerocks::nbapi::ambiorix_func_ptr get_access_point_commit(void) { return access_point_commit; }

} // namespace actions
} // namespace controller
} // namespace prplmesh
