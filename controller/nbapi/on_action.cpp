/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "on_action.h"

namespace prplmesh {
namespace controller {

// Actions

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
        LOG(WARNING) << "Failed to get object Controller.Network.AccessPoint.Security";
        return;
    }
    rm_params(security_obj, "PreSharedKey");
    rm_params(security_obj, "KeyPassphrase");
    rm_params(security_obj, "SAEPassphrase");
}

static void add_string_param(const char *param_name, amxd_object_t *param_owner_obj)
{
    amxd_param_t *param = NULL;

    amxd_param_new(&param, param_name, AMXC_VAR_ID_CSTRING);
    amxd_object_add_param(param_owner_obj, param);
    amxd_param_add_action_cb(param, action_param_read, display_empty_val, NULL);
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
        {"event_add_hidden_params", event_add_hidden_params},
        {"event_rm_params", event_rm_params},
    };
    return events_list;
}

} // namespace controller
} // namespace prplmesh
