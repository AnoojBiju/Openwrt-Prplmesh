/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include "ambiorix_impl.h"

namespace beerocks {
namespace nbapi {

AmbiorixImpl::AmbiorixImpl(std::shared_ptr<EventLoop> event_loop) : m_event_loop(event_loop)
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
        LOG(ERROR) << "Couldn't inititalize transaction, status: " << status;
        return nullptr;
    }

    status = amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't set transaction attributes, status: " << status;
        return nullptr;
    }

    status = amxd_trans_select_object(&transaction, object);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't select transaction object, status: " << status;
        return nullptr;
    }

    return object;
}

bool AmbiorixImpl::apply_transaction(amxd_trans_t &transaction)
{
    auto ret    = true;
    auto status = amxd_trans_apply(&transaction, &m_datamodel);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't apply transaction object, status: " << status;
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(cstring_t, &transaction, parameter.c_str(), value.c_str());

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(int32_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(int64_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(uint32_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(uint64_t, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(double, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
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
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    LOG(DEBUG) << "Set " << object->name << "." << parameter << " to " << value;

    amxd_trans_set_value(bool, &transaction, parameter.c_str(), value);

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Couldn't apply transaction.";
        return false;
    }

    return true;
}

uint32_t AmbiorixImpl::add_instance(const std::string &relative_path)
{
    amxd_trans_t transaction;
    uint32_t index;

    auto object = prepare_transaction(relative_path, transaction);
    if (!object) {
        LOG(ERROR) << "Couldn't find the object for: " << relative_path;
        return 0;
    }

    auto status = amxd_trans_add_inst(&transaction, 0, NULL);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Failed to add instance for: " << object->name << " status: " << status;
    }

    if (!apply_transaction(transaction)) {
        LOG(ERROR) << "Failed to apply transaction for: " << object->name;
        return 0;
    }

    index = amxd_object_get_index(transaction.current);
    if (!index) {
        LOG(ERROR) << "Failed to get index for object: " << transaction.current->name;
    }

    LOG(DEBUG) << "Instance " << transaction.current->name << " added for: " << object->name;
    return index;
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
        LOG(ERROR) << "Failed to apply transaction for: " << object->name;
        return false;
    }

    LOG(DEBUG) << "Instance removed for: " << object->name;
    return true;
}

uint32_t AmbiorixImpl::get_instance_index(const std::string &specific_path, const std::string &key)
{
    uint32_t index = 0;

    auto object = amxd_dm_findf(&m_datamodel, specific_path.c_str(), key.c_str());
    if (!object) {
        LOG(ERROR) << "Failed to find object by key: " << specific_path << " for id: " << key;
        return index;
    }

    index = amxd_object_get_index(object);
    if (!index) {
        LOG(ERROR) << "Failed to get index for object: " << object->name;
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

uint32_t AmbiorixImpl::get_parent_instance_index(const std::string &specific_path,
                                                 const std::string &key)
{
    uint32_t index = 0;

    auto object = amxd_dm_findf(&m_datamodel, specific_path.c_str(), key.c_str());
    if (!object) {
        LOG(ERROR) << "Failed to find object by key: " << specific_path << " for key: " << key;
        return index;
    }

    auto parent_object = amxd_object_get_parent(object);
    if (!object) {
        LOG(ERROR) << "Failed to get parent object, path: " << specific_path << " for key: " << key;
        return index;
    }

    index = amxd_object_get_index(parent_object);
    if (!index) {
        LOG(ERROR) << "Failed to get parent index for object: " << object->name;
        return index;
    }

    return index;
}

AmbiorixImpl::~AmbiorixImpl()
{
    remove_event_loop();
    remove_signal_loop();
    amxb_free(&m_bus_ctx);
    amxd_dm_clean(&m_datamodel);
    amxo_parser_clean(&m_parser);
    amxb_be_remove_all();
}
} // namespace nbapi
} // namespace beerocks
