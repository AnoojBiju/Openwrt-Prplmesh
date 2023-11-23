/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include "ambiorix_impl.h"
#include "tlvf/tlvftypes.h"

#include <bcl/beerocks_backport.h>
#include <bcl/network/network_utils.h>

#include <memory>

namespace beerocks {
namespace nbapi {

namespace {
namespace priv {
struct Transaction : Ambiorix::SingleObjectTransaction {
    AmbiorixImpl *parent;
    std::string relative_path;
    bool new_instance;
    amxd_trans_t transaction;

    ~Transaction() override { amxd_trans_clean(&transaction); }

#define TRANS_SET(TYPE)                                                                            \
    bool set(const std::string &parameter, const TYPE &value) override                             \
    {                                                                                              \
        return amxd_trans_set_value(TYPE, &transaction, parameter.c_str(), value) ==               \
               amxd_status_ok;                                                                     \
    }
    TRANS_SET(int8_t)
    TRANS_SET(int16_t)
    TRANS_SET(int32_t)
    TRANS_SET(int64_t)
    TRANS_SET(uint8_t)
    TRANS_SET(uint16_t)
    TRANS_SET(uint32_t)
    TRANS_SET(uint64_t)
    TRANS_SET(bool)
    TRANS_SET(double)
    bool set(const std::string &parameter, const char *value) override
    {
        return amxd_trans_set_value(cstring_t, &transaction, parameter.c_str(), value) ==
               amxd_status_ok;
    }
#undef TRANS_SET

    bool set(const std::string &parameter, const sMacAddr &value) override
    {
        return set(parameter, tlvf::mac_to_string(value));
    }

    using SingleObjectTransaction::set;

    bool set_time(const std::string &time_stamp) override
    {
        amxc_ts_t time;
        if (amxc_ts_parse(&time, time_stamp.c_str(), time_stamp.size()) != 0) {
            LOG(ERROR) << " time_stamp: " << time_stamp
                       << " does not contain a valid unix epoch time!";
            return false;
        }

        if (!set("TimeStamp", time_stamp)) {
            LOG(ERROR) << "Failed to set " << relative_path << ".TimeStamp";
            return false;
        }
        return true;
    }

    bool set_current_time(const std::string &param) override
    {
        auto time_stamp = parent->get_datamodel_time_format();

        return !time_stamp.empty() && set(param, time_stamp);
    }
};
} // namespace priv
} // namespace

amxd_dm_t *g_data_model = nullptr;

AmbiorixImpl::AmbiorixImpl(std::shared_ptr<EventLoop> event_loop,
                           const std::vector<sActionsCallback> &on_action,
                           const std::vector<sEvents> &events,
                           const std::vector<sFunctions> &funcs_list)
    : m_event_loop(event_loop), m_on_action_handlers(on_action), m_events_list(events),
      m_func_list(funcs_list)
{
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";
    amxo_parser_init(&m_parser);
    amxd_dm_init(&m_datamodel);
}

bool AmbiorixImpl::init(const std::string &amxb_backend, const std::string &bus_uri,
                        const std::string &datamodel_path)
{
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

    if (!load_datamodel(datamodel_path)) {
        LOG(ERROR) << "Failed to load data model.";
        return false;
    }

    status = amxb_register(m_bus_ctx, &m_datamodel);
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
    g_data_model = &m_datamodel;
    return true;
}

bool AmbiorixImpl::load_datamodel(const std::string &datamodel_path)
{
    LOG(DEBUG) << "Loading the data model.";
    auto *root_obj = amxd_dm_get_root(&m_datamodel);
    if (!root_obj) {
        LOG(ERROR) << "Failed to get datamodel root object.";
        return false;
    }

    for (const auto &action : m_on_action_handlers) {
        auto ret = amxo_resolver_ftab_add(&m_parser, action.action_name.c_str(),
                                          reinterpret_cast<amxo_fn_ptr_t>(action.callback));
        if (ret != 0) {
            LOG(WARNING) << "Failed to add " << action.action_name;
            continue;
        }
        LOG(DEBUG) << "Added " << action.action_name << " to the functions table.";
    }
    for (const auto &event : m_events_list) {
        auto ret = amxo_resolver_ftab_add(&m_parser, event.name.c_str(),
                                          reinterpret_cast<amxo_fn_ptr_t>(event.callback));
        if (ret != 0) {
            LOG(WARNING) << "Failed to add " << event.name;
            continue;
        }
        LOG(DEBUG) << "Added " << event.name << " to the functions table.";
    }
    for (const auto &func : m_func_list) {
        auto ret = amxo_resolver_ftab_add(&m_parser, func.path.c_str(), AMXO_FUNC(func.callback));
        if (ret != 0) {
            LOG(WARNING) << "Failed to add " << func.name;
            continue;
        }
        LOG(DEBUG) << "Added " << func.name << " to the functions table.";
    }

    // Disable eventing while loading odls
    amxp_sigmngr_enable(&m_datamodel.sigmngr, false);

    amxo_parser_parse_file(&m_parser, datamodel_path.c_str(), root_obj);

    amxp_sigmngr_enable(&m_datamodel.sigmngr, true);

    LOG(DEBUG) << "The data model loaded successfully.";
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

    auto object = amxd_dm_findf(&m_datamodel, "%s", relative_path.c_str());
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
    auto status = amxd_trans_apply(&transaction, &m_datamodel);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't apply transaction object, status: " << amxd_status_string(status);
        ret = false;
    }

    amxd_trans_clean(&transaction);

    return ret;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              int8_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(int8_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              int16_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(int16_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              int32_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(int32_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              int64_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(int64_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              uint8_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(uint8_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}
bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              uint16_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(uint16_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              uint32_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(uint32_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              uint64_t *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(uint64_t, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              double *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(double, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              bool *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = 0;
        return false;
    }
    *param_val = amxc_var_constcast(bool, &ret_val);
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              std::string *param_val)
{
    amxc_var_t ret_val;
    amxd_object_t *obj = find_object(obj_path);
    if (!obj) {
        LOG(ERROR) << "Failed to find \"" << obj_path << "\"";
        return false;
    }
    amxd_status_t status = amxd_object_get_param(obj, param_name.c_str(), &ret_val);

    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path;
        *param_val = "";
        return false;
    }
    *param_val = std::string(amxc_var_constcast(cstring_t, &ret_val));
    amxc_var_clean(&ret_val);
    return true;
}

bool AmbiorixImpl::read_param(const std::string &obj_path, const std::string &param_name,
                              sMacAddr *param_val)
{
    std::string mac_string;
    bool str_ret_val = read_param(obj_path, param_name, &mac_string);
    if (!str_ret_val) {
        *param_val = beerocks::net::network_utils::ZERO_MAC;
        return false;
    }
    bool mac_is_valid = tlvf::mac_from_string(param_val->oct, mac_string);
    if (!mac_is_valid) {
        LOG(ERROR) << "Failed to get param [" << param_name << "] of object: " << obj_path
                   << ". Object is not a MAC Address";
        *param_val = beerocks::net::network_utils::ZERO_MAC;
        return false;
    }
    return true;
}

std::unique_ptr<Ambiorix::SingleObjectTransaction>
AmbiorixImpl::begin_transaction(const std::string &relative_path, bool new_instance)
{
    auto ret = std::make_unique<priv::Transaction>();

    ret->parent        = this;
    ret->relative_path = relative_path;
    ret->new_instance  = new_instance;

    if (!prepare_transaction(relative_path, ret->transaction)) {
        LOG(ERROR) << "Failed to prepare transaction: " << relative_path;
        return {};
    }

    if (!new_instance) {
        return ret;
    }

    auto status = amxd_trans_add_inst(&ret->transaction, 0, NULL);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to add instance for: " << relative_path
                   << " status: " << amxd_status_string(status);
        return {};
    }

    return ret;
}

std::string AmbiorixImpl::commit_transaction(std::unique_ptr<SingleObjectTransaction> trans)
{
    auto derived = static_cast<priv::Transaction *>(trans.get());

    auto &transaction = derived->transaction;
    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction";
        return {};
    }

    auto relative_path = std::move(derived->relative_path);
    if (!derived->new_instance) {
        return relative_path;
    }

    auto index = amxd_object_get_index(transaction.current);
    if (!index) {
        LOG(ERROR) << "Failed to get index for object: " << transaction.current->name;
        return {};
    }

    relative_path += '.';
    relative_path += std::to_string(index);

    return relative_path;
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

    auto object = amxd_dm_findf(&m_datamodel, specific_path.c_str(), key.c_str());
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

AmbiorixImpl::~AmbiorixImpl()
{
    remove_event_loop();
    remove_signal_loop();
    amxb_free(&m_bus_ctx);
    amxd_dm_clean(&m_datamodel);
    amxo_parser_clean(&m_parser);
}

} // namespace nbapi
} // namespace beerocks
