/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "ambiorix_impl.h"
#include "tlvf/tlvftypes.h"

#include <functional>
#include <event2/event.h>

namespace beerocks {
namespace nbapi {

amxd_dm_t *g_data_model = nullptr;
static struct event* signal_alarm = NULL;

AmbiorixImpl::AmbiorixImpl(std::shared_ptr<EventLoop> event_loop,
                           const std::vector<sActionsCallback> &on_action,
                           const std::vector<sEvents> &events,
                           const std::vector<sFunctions> &funcs_list)
    :AmbiorixOdlManager(),m_event_loop(event_loop), m_on_action_handlers(on_action), m_events_list(events), m_func_list(funcs_list)
{
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";
}


static void el_signal_timers(evutil_socket_t fd,
                             short event,
                             void* arg) {
    amxp_timers_calculate();
    amxp_timers_check();
}

bool AmbiorixImpl::init(const std::string &amxb_backend, const std::string &bus_uri,
                        const std::string &datamodel_path)
{
    LOG(INFO) << "AmbiorixImpl::init ";
    LOG(DEBUG) << "Initializing the bus connection.";
    int status = 0;

    status = amxb_be_load(amxb_backend.c_str());
    if (status != 0) {
        LOG(ERROR) << "Failed to load backend, status: " << status;
        return false;
    }

    // Connect to the bus
    status = amxb_connect(&m_bus_ctx, bus_uri.c_str());
    if (status != 0) {
        LOG(ERROR) << "Failed to connect to the bus, status: " << status;
        return false;
    }

    if (!load_datamodel()) {
        LOG(ERROR) << "Failed to load data model.";
        return false;
    }
    AmbiorixOdlManager::loadRootDM(datamodel_path);
    AmbiorixOdlManager::populateDataModel();

    status = amxb_register(m_bus_ctx, AMXOParser::getDatamodel());
    if (status != 0) {
        LOG(ERROR) << "Failed to register the data model.";
        return false;
    }

    if (!init_event_loop()) {
        LOG(ERROR) << "Failed to initialize event loop.";
        return false;
    }

    if (!init_signal_loop()) {
        LOG(ERROR) << "Failed to initialize event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }
    LOG(DEBUG) << "The bus connection initialized successfully.";


    struct event_base* base = event_base_new();

    signal_alarm = evsignal_new(base ,
                                SIGALRM,
                                el_signal_timers,
                                NULL);

    event_add(signal_alarm, NULL);

    g_data_model = AMXOParser::getDatamodel();
    return true;
}

static bool pcm_svc_flags_contains_upc_params(const amxc_llist_t* flags, pcm_type_t type) {
    LOG(INFO) << ">>>>> pcm_svc_flags_contains_upc_params : ";

    AMXCListContainer flags_c(flags);

    for(auto it : flags_c) {
        amxc_var_t* flag = amxc_var_from_llist_it(it);
        std::string flag_str = GET_CHAR(flag, NULL);
        LOG(INFO) << ">>>>> pcm_svc_flags_contains_upc_params flag_str : "<<flag_str;

        if((type == pcm_type_upc) && (strcmp(GET_CHAR(flag, NULL), "upc") == 0)) {
            return true;
        } else if((type == pcm_type_usersetting) && (strcmp(GET_CHAR(flag, NULL), "usersetting") == 0)) {
            return true;
        }
    }

    amxc_llist_for_each(it, flags) {

    }
    return false;
}
bool AmbiorixImpl::pcm_svc_has_upc_params(amxd_object_t* object, pcm_type_t type) {
    bool retval = false;
    amxc_var_t params;
    const amxc_htable_t* ht_params = NULL;

    amxc_var_init(&params);

    amxd_object_describe_params(object, &params, amxd_dm_access_public);

    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    amxc_htable_for_each(it, ht_params) {
        amxc_var_t* param = amxc_var_from_htable_it(it);
        const amxc_llist_t* flags = amxc_var_constcast(amxc_llist_t,
                                                       GET_ARG(param, "flags"));
        if(pcm_svc_flags_contains_upc_params(flags, type)) {
            retval = true;
            break;
        }
    }

    amxc_var_clean(&params);
    return retval;
}




void AmbiorixImpl::pcm_svc_param_changed(const char* const sig_name,
                                         const amxc_var_t* const data,
                                         void* const priv) {
    (void) sig_name;
    amxd_object_t* object = amxd_dm_signal_get_object(AMXOParser::getDatamodel(), data);
    amxd_param_t* param_def = NULL;
    amxc_var_t* params = GET_ARG(data, "parameters");

    LOG(INFO) << "Received SIGNAL "<< sig_name;

    amxc_var_for_each(param, params) {
        const char* param_name = amxc_var_key(param);
        param_def = amxd_object_get_param_def(object, param_name);
        if(amxd_param_has_flag(param_def, "upc") || amxd_param_has_flag(param_def, "usersetting")) {
            LOG(INFO) << "Set flag upc_changed - param_name: "<<param_name;
            amxd_param_set_flag(param_def, "upc_changed");
        }
    }
}

bool AmbiorixImpl::load_datamodel()
{
    LOG(DEBUG) << "Loading the data model.";
    auto *root_obj = amxd_dm_get_root(AMXOParser::getDatamodel());
    if (!root_obj) {
        LOG(ERROR) << "Failed to get datamodel root object.";
        return false;
    }

    for (const auto &action : m_on_action_handlers) {
        auto ret = amxo_resolver_ftab_add(AMXOParser::getParser(), action.action_name.c_str(),
                                          reinterpret_cast<amxo_fn_ptr_t>(action.callback));
        if (ret != 0) {
            LOG(WARNING) << "Failed to add " << action.action_name;
            continue;
        }
        LOG(DEBUG) << "Added " << action.action_name << " to the functions table.";
    }
    for (const auto &event : m_events_list) {
        auto ret = amxo_resolver_ftab_add(AMXOParser::getParser(), event.name.c_str(),
                                          reinterpret_cast<amxo_fn_ptr_t>(event.callback));
        if (ret != 0) {
            LOG(WARNING) << "Failed to add " << event.name;
            continue;
        }
        LOG(DEBUG) << "Added " << event.name << " to the functions table.";
    }
    for (const auto &func : m_func_list) {
        auto ret = amxo_resolver_ftab_add(AMXOParser::getParser(), func.path.c_str(), AMXO_FUNC(func.callback));
        if (ret != 0) {
            LOG(WARNING) << "Failed to add " << func.name;
            continue;
        }
        LOG(DEBUG) << "Added " << func.name << " to the functions table.";
    }

    return true;
}

bool AmbiorixImpl::init_event_loop()
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix fd in the event loop.";

    auto ambiorix_fd = amxb_get_fd(m_bus_ctx);
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_events",
        .on_read =
        [&](int fd, EventLoop &loop) {
            amxb_read(m_bus_ctx);
            return true;
        },

        // Not implemented
        .on_write      = nullptr,
        .on_disconnect = nullptr,

        // Handle interface errors
        .on_error =
        [&](int fd, EventLoop &loop) {
            LOG(ERROR) << "Error on ambiorix fd.";
            return true;
        },
    };

    if (!m_event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix fd in the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool AmbiorixImpl::init_signal_loop()
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix signals fd in the event loop.";

    auto ambiorix_fd = amxp_signal_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_signal",
        .on_read =
        [&](int fd, EventLoop &loop) {
            amxp_signal_read();
            return true;
        },
        // Not implemented
        .on_write      = nullptr,
        .on_disconnect = nullptr,

        // Handle interface errors
        .on_error =
        [&](int fd, EventLoop &loop) {
            LOG(ERROR) << "Error on ambiorix fd.";
            return true;
        },
    };

    if (!m_event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix signals fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool AmbiorixImpl::remove_event_loop()
{
    LOG(DEBUG) << "Remove event handlers for Ambiorix fd from the event loop.";

    auto ambiorix_fd = amxb_get_fd(m_bus_ctx);
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    if (!m_event_loop->remove_handlers(ambiorix_fd)) {
        LOG(ERROR) << "Couldn't remove event handlers for the Ambiorix fd from the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd successfully removed from the event loop.";

    return true;
}

bool AmbiorixImpl::remove_signal_loop()
{
    LOG(DEBUG) << "Remove event handlers for the Ambiorix signals fd from the event loop.";

    auto ambiorix_fd = amxp_signal_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    if (!m_event_loop->remove_handlers(ambiorix_fd)) {
        LOG(ERROR) << "Couldn't remove event handlers for the Ambiorix signals fd from the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "The event handlers for the Ambiorix signals fd removed successfully from the "
                  "event loop.";

    return true;
}

amxd_object_t *AmbiorixImpl::find_object(const std::string &relative_path)
{

    auto object = amxd_dm_findf(AMXOParser::getDatamodel(), "%s", relative_path.c_str());
    if (!object) {
        LOG(ERROR) << "Failed to get object from data model when searching for: " << relative_path;
        return nullptr;
    }

    return object;
}

bool AmbiorixImpl::add_optional_subobject(const std::string &path_to_obj,
                                          const std::string &subobject_name)
{
    amxd_object_t *object = find_object(path_to_obj);

    if (!object) {
        LOG(ERROR) << "Failed to add mib [" << subobject_name << "] for " << path_to_obj;
        return false;
    }

    amxd_status_t status = amxd_object_add_mib(object, subobject_name.c_str());
    if (status == amxd_status_duplicate) {
        LOG(ERROR) << "Mib [" << subobject_name << "] already present in object: " << path_to_obj;
        return false;
    }

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to add mib [" << subobject_name << "] for " << path_to_obj;
        return false;
    }

    LOG(DEBUG) << "Mib [" << subobject_name << "] successfully added for object " << path_to_obj;

    return true;
}

bool AmbiorixImpl::remove_optional_subobject(const std::string &path_to_obj,
                                             const std::string &subobject_name)
{
    amxd_object_t *object = find_object(path_to_obj);

    if (!object) {
        LOG(ERROR) << "Failed to remove mib [" << subobject_name << "] from " << path_to_obj;
        return false;
    }

    amxd_status_t status = amxd_object_remove_mib(object, subobject_name.c_str());
    if (status == amxd_status_object_not_found) {
        LOG(ERROR) << "Object [" << path_to_obj << "] not found.";
        return false;
    }

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to remove mib [" << subobject_name << "] for " << path_to_obj;
        return false;
    }

    LOG(DEBUG) << "Mib [" << subobject_name << "] successfully removed from " << path_to_obj;

    return true;
}

amxd_object_t *AmbiorixImpl::prepare_transaction(const std::string &relative_path,
                                                 amxd_trans_t &transaction)
{
    auto object = find_object(relative_path);
    if (!object) {
        LOG(ERROR) << "Couldn't get object by relative path.";
        return nullptr;
    }

    auto status = amxd_trans_init(&transaction);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't inititalize transaction, status: " << amxd_status_string(status);
        return nullptr;
    }

    status = amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't set transaction attributes, status: " << amxd_status_string(status);
        return nullptr;
    }

    status = amxd_trans_select_object(&transaction, object);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't select transaction object, status: " << amxd_status_string(status);
        return nullptr;
    }

    return object;
}

bool AmbiorixImpl::apply_transaction(amxd_trans_t &transaction)
{
    auto ret    = true;
    auto status = amxd_trans_apply(&transaction, AMXOParser::getDatamodel());
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't apply transaction object, status: " << amxd_status_string(status);
        ret = false;
    }

    amxd_trans_clean(&transaction);

    return ret;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const std::string &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << "." << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(cstring_t, &transaction, parameter.c_str(), value.c_str());

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << "." << parameter << "="
                   << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const int8_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    amxd_trans_set_value(int8_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const int16_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    amxd_trans_set_value(int16_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const int32_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(int32_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const int64_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(int64_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const uint8_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    amxd_trans_set_value(uint8_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const uint16_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    amxd_trans_set_value(uint16_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const uint32_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(uint32_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const uint64_t &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(uint64_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const double &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(double, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const bool &value)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);

    if (!object) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path << parameter << "="
                   << value;
        return false;
    }

    // LOG(DEBUG) << "Set " << relative_path << "." << parameter << ": " << value;

    amxd_trans_set_value(bool, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction: " << relative_path << parameter << "=" << value;
        return false;
    }

    return true;
}

bool AmbiorixImpl::set(const std::string &relative_path, const std::string &parameter,
                       const sMacAddr &value)
{
    return set(relative_path, parameter, tlvf::mac_to_string(value));
}

std::string AmbiorixImpl::add_instance(const std::string &relative_path)
{
    amxd_trans_t transaction;
    uint32_t index;

    auto object = prepare_transaction(relative_path, transaction);
    if (!object) {
        LOG(ERROR) << "Couldn't find the object for: " << relative_path;
        return {};
    }

    auto status = amxd_trans_add_inst(&transaction, 0, NULL);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to add instance for: " << relative_path
                   << " status: " << amxd_status_string(status);
    }

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Failed to apply transaction for: " << relative_path;
        return {};
    }

    index = amxd_object_get_index(transaction.current);
    if (!index) {
        LOG(ERROR) << "Failed to get index for object: " << transaction.current->name;
    }

    LOG(DEBUG) << "Instance " << transaction.current->name << " added for: " << relative_path;
    return relative_path + "." + std::to_string(index);
}

bool AmbiorixImpl::remove_instance(const std::string &relative_path, uint32_t index)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);
    if (!object) {
        LOG(ERROR) << "Couldn't find the object for: " << relative_path;
        return false;
    }

    amxd_object_for_each(instance, it, object)
    {
        auto inst               = amxc_llist_it_get_data(it, amxd_object_t, it);
        auto current_inst_index = amxd_object_get_index(inst);
        if (current_inst_index == index) {
            amxd_trans_del_inst(&transaction, amxd_object_get_index(inst), NULL);
            break;
        }
    }

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Failed to apply transaction for: " << relative_path;
        return false;
    }

    LOG(DEBUG) << "Instance removed for: " << relative_path << "." << index;
    return true;
}

uint32_t AmbiorixImpl::get_instance_index(const std::string &specific_path, const std::string &key)
{
    uint32_t index = 0;

    auto object = amxd_dm_findf(AMXOParser::getDatamodel(), specific_path.c_str(), key.c_str());
    if (!object) {
        return index;
    }

    index = amxd_object_get_index(object);
    if (!index) {
        return index;
    }

    return index;
}

std::string AmbiorixImpl::get_datamodel_time_format()
{

    amxc_ts_t datamodel_time;

    if (amxc_ts_now(&datamodel_time)) {
        LOG(ERROR) << "Failed to get current time in data model format.";
        return "";
    }

    const size_t buf_size = 64;
    char buf[buf_size];

    if (!amxc_ts_format(&datamodel_time, buf, buf_size)) {
        LOG(ERROR) << "Failed to get date and time in RFC 3339 format.";
        return "";
    }

    std::string result_time = buf;
    return result_time;
}

bool AmbiorixImpl::set_current_time(const std::string &path_to_object, const std::string &param)
{
    auto time_stamp = get_datamodel_time_format();

    if (time_stamp.empty()) {
        LOG(ERROR) << "Failed to get Date and Time in RFC 3339 format.";
        return false;
    }
    if (!set(path_to_object, param, time_stamp)) {
        LOG(ERROR) << "Failed to set " << path_to_object << "." << param << ": " << time_stamp;
        return false;
    }
    return true;
}

bool AmbiorixImpl::set_time(const std::string &path_to_object, const std::string &time_stamp)
{
    std::string time_stamp_local(time_stamp);

    amxc_ts_t time;
    if (amxc_ts_parse(&time, time_stamp.c_str(), time_stamp.size()) != 0) {
        LOG(ERROR) << " time_stamp: " << time_stamp << " does not contain a valid unix epoch time!";
        return false;
    }

    if (!set(path_to_object, "TimeStamp", time_stamp_local)) {
        LOG(ERROR) << "Failed to set " << path_to_object << ".TimeStamp";
        return false;
    }
    return true;
}

bool AmbiorixImpl::remove_all_instances(const std::string &relative_path)
{
    amxd_trans_t transaction;
    auto object = prepare_transaction(relative_path, transaction);
    if (!object) {
        LOG(ERROR) << "Couldn't find the object for: " << relative_path;
        return false;
    }

    amxd_object_for_each(instance, it, object)
    {
        auto inst = amxc_llist_it_get_data(it, amxd_object_t, it);
        amxd_trans_del_inst(&transaction, amxd_object_get_index(inst), nullptr);
    }

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Failed to apply transaction for: " << relative_path;
        return false;
    }

    LOG(DEBUG) << "All instances removed for: " << relative_path;
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              uint64_t *param_val)
{
    auto obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }

    amxc_var_t ret_val;
    amxc_var_init(&ret_val);
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        amxc_var_clean(&ret_val);
        return false;
    }

    *param_val = amxc_var_constcast(uint64_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              std::string *param_val)
{
    auto obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }

    amxc_var_t ret_val;
    amxc_var_init(&ret_val);
    auto status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        amxc_var_clean(&ret_val);
        return false;
    }

    *param_val = amxc_var_constcast(cstring_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

AmbiorixImpl::~AmbiorixImpl()
{
    remove_event_loop();
    remove_signal_loop();
    amxb_free(&m_bus_ctx);
}

} // namespace nbapi
} // namespace beerocks
