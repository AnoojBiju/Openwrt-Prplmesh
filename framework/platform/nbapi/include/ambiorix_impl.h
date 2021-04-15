/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_IMPL
#define AMBIORIX_IMPL

// prplmesh
#include <bcl/beerocks_event_loop.h>
#include <easylogging++.h>
#include <mapf/common/utils.h>

// Ambiorix
#include <amxc/amxc.h>
#include <amxc/amxc_variant.h>
#include <amxc/amxc_variant_type.h>
#include <amxp/amxp.h>

#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include <amxb/amxb.h>
#include <amxb/amxb_operators.h>
#include <amxb/amxb_register.h>

#include <amxo/amxo.h>
#include <amxo/amxo_save.h>

#include "ambiorix.h"

namespace beerocks {
namespace nbapi {

using actions_callback = amxd_status_t (*)(amxd_object_t *object, amxd_param_t *param,
                                           amxd_action_t reason, const amxc_var_t *const args,
                                           amxc_var_t *const retval, void *priv);

using events_callback = void (*)(const char *const sig_name, const amxc_var_t *const data,
                                 void *const priv);

using ambiorix_func_ptr = amxd_status_t (*)(amxd_object_t *object, amxd_function_t *func,
                                            amxc_var_t *args, amxc_var_t *ret);

typedef struct sActionsCallback {
    std::string action_name;
    actions_callback callback;
} sActionsCallback;

typedef struct sEvents {
    std::string name;
    events_callback callback;
} sEvents;

typedef struct sFunctions {
    std::string name;
    std::string path;
    ambiorix_func_ptr callback;
} sFunctions;

extern amxd_dm_t *g_data_model;

/**
 * @class AmbiorixImpl
 * @brief This class manages the ambiorixImpl instance.
 */
class AmbiorixImpl : public Ambiorix {

public:
    explicit AmbiorixImpl(std::shared_ptr<EventLoop> event_loop,
                          const std::vector<sActionsCallback> &on_action,
                          const std::vector<sEvents> &events,
                          const std::vector<sFunctions> &funcs_list);

    /**
     * @brief AmbiorixImpl destructor removes: bus connection, data model, parser and all data
     *        from the backend (UBus, PCB, etc.).
     */
    ~AmbiorixImpl() override;

    /**
     * @brief Initialize the ambiorix library: load backend, connect to the bus, load data model,
     *        register data model in the bus.
     *
     * @param amxb_backend Path to the ambiorix backend (ex: "/usr/bin/mods/amxb/mod-amxb-ubus.so").
     * @param bus_uri Path to the bus in uri form (ex: "ubus:/var/run/ubus.sock").
     * @param datamodel_path Path to the data model definition ODL file.
     * @return True on success and false otherwise.
     */
    bool init(const std::string &amxb_backend, const std::string &bus_uri,
              const std::string &datamodel_path);

    bool set(const std::string &relative_path, const std::string &parameter,
             const std::string &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int32_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int64_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint32_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint64_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const bool &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const double &value) override;

    std::string add_instance(const std::string &relative_path) override;

    bool remove_instance(const std::string &relative_path, uint32_t index) override;

    uint32_t get_instance_index(const std::string &specific_path, const std::string &key) override;

    std::string get_datamodel_time_format() override;

    bool remove_all_instances(const std::string &relative_path) override;

    bool add_optional_subobject(const std::string &path_to_obj,
                                const std::string &subobject_name) override;

    bool remove_optional_subobject(const std::string &path_to_obj,
                                   const std::string &subobject_name) override;

    /**
     * @brief Get data from bus from path with specific method.
     *
     * This method should only be used after init(). It uses m_bus_ctx is inside.
     * Note that m_bus_ctx is not thread safe.
     *
     * Field parameter is used to search specific data member inside returned answer from call.
     * See examples below.
     *
     * If key contains '.', either put key in quotes like in example or add '/' before inside field arg.
     *
     * Examples of search examples:
     * get_data_from_bus("luci-rpc", "getDHCPLeases", "dhcp_leases", "macaddr == '00:3A:4C:68:01:F5'");
     * Returns duid:01:00:e0:4c:00:01:00,macaddr:00:3A:4C:68:01:F5,hostname:xxxx,expires:39222,ipaddr:192.168.3.216
     *
     * get_data_from_bus("luci-rpc", "getDHCPLeases", "dhcp_leases");
     * Returns all leases as below with semicolon separeted.
     * duid:01:00:00:fc:e9:00:25,macaddr:AA:DD:FC:E9:F1:25,expires:39185,ipaddr:192.168.3.104;
     * duid:01:00:e0:4c:00:01:00,macaddr:00:3A:4C:68:01:F5,hostname:lenovo,expires:39222,ipaddr:192.168.3.216
     *
     * get_data_from_bus("Agent", "get", "'Agent.'.MACAddress")
     * Returns "11:3A:1A:22:01:12", agent mac address
     *
     * get_data_from_bus("Controller.Network.Device.1.Radio", "list", "instances.0.name")
     * Returns "1", first index of radio instance
     *
     * @param specific_path Path to the data model definition ODL file.
     * @param method Path to the data model definition ODL file.
     * @param field Field
     * @param filter Optional paramater. It filters only list to match a member.
     * @return True on success and false otherwise.
     */

    std::string get_data_from_bus(const std::string &specific_path, const std::string &method,
                                  const std::string &field,
                                  const std::string &filter = std::string()) override;

private:
    // Methods

    /**
     * @brief Prepare transaction to the ubus
     *
     * @param relative_path Path to the object in datamodel (ex: "Controller.Network.ID").
     * @param transaction Variable for transaction structure which contains fields
     *                    needed for transaction.
     * @return Pointer on the object on success and nullptr otherwise.
     */
    amxd_object_t *prepare_transaction(const std::string &relative_path, amxd_trans_t &transaction);

    /**
     * @brief Apply transaction
     *
     * @param transaction Variable for transaction structure which contains fields
     *                    needed for transaction.
     * @return True on success and false otherwise.
     */
    bool apply_transaction(amxd_trans_t &transaction);

    /**
     * @brief Load and parse data model from the ODL file.
     *
     * @param datamodel_path Path to the data model definition ODL file.
     * @return True on success and false otherwise.
     */
    bool load_datamodel(const std::string &datamodel_path);

    /**
     * @brief Initialize event handlers for Ambiorix fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool init_event_loop();

    /**
     * @brief Initialize event handlers for the ambiorix signals fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool init_signal_loop();

    /**
     * @brief Remove event handlers for Ambiorix fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool remove_event_loop();

    /**
     * @brief Remove event handlers for the ambiorix signals fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool remove_signal_loop();

    /**
     * @brief Find object by relative path.
     *
     * @param relative_path Path to the object in datamodel (ex: "Controller.Network.ID").
     * @return Pointer on the object on success and nullptr otherwise.
     */
    amxd_object_t *find_object(const std::string &relative_path);

    // Variables
    amxb_bus_ctx_t *m_bus_ctx = nullptr;
    amxd_dm_t m_datamodel;
    amxo_parser_t m_parser;
    std::shared_ptr<EventLoop> m_event_loop;
    //std::unordered_map<std::string, actions_callback> m_on_action_handlers;
    std::vector<sActionsCallback> m_on_action_handlers;
    std::vector<sEvents> m_events_list;
    std::vector<sFunctions> m_func_list;
};

} // namespace nbapi
} // namespace beerocks

#endif
