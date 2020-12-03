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

std::vector<beerocks::nbapi::sActionsCallback> get_actions_callback_list(void)
{
    const std::vector<beerocks::nbapi::sActionsCallback> actions_list = {
        {"action_read_last_change", action_read_last_change},
        {"display_empty_val", display_empty_val},
    };
    return actions_list;
}

} // namespace controller
} // namespace prplmesh
