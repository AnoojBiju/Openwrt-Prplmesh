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
#include <amxp/amxp.h>

#include <amxc/amxc.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

#include <amxo/amxo.h>
#include <amxo/amxo_save.h>

#include "ambiorix.h"

namespace beerocks {
namespace nbapi {

using actions_callback = amxd_status_t (*)(amxd_object_t *object, amxd_param_t *param,
                                           amxd_action_t reason, const amxc_var_t *const args,
                                           amxc_var_t *const retval, void *priv);
typedef struct sActionsCallback {
    std::string action_name;
    actions_callback callback;
} sActionsCallback;

/**
 * @class AmbiorixImpl
 * @brief This class manages the ambiorixImpl instance.
 */
class AmbiorixImpl : public Ambiorix {

public:
    explicit AmbiorixImpl(std::shared_ptr<EventLoop> event_loop,
                          const std::vector<sActionsCallback> &on_action);

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

    /**
     * @brief Set the value to the object variable.
     *
     * @param relative_path Path to the object in datamodel (ex: "Controller.Network").
     * @param parameter The parameter to be set (ex: "ID").
     * @param value Value which need to set.
     * @return True on success and false otherwise.
     */
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

    /* @brief Add instance to the data model object with type list
     *
     * @param relative_path Path to the object with type list in datamodel (ex: "Controller.Network.Device").
     * @return index of recently added object on success, 0 otherwise
     */
    uint32_t add_instance(const std::string &relative_path) override;

    /**
     * @brief Remove instance from the data model object with type list
     *
     * @param relative_path Path to the object with type list in datamodel (ex: "Controller.Network.Device").
     * @param index Number of instance which should be remove.
     * @return True on success and false otherwise.
     */
    bool remove_instance(const std::string &relative_path, uint32_t index) override;

    /**
     * @brief Get instance index by ID.
     *
     * @param specific_path Path to the object specific key (ex: "Device.[ID == '%s'].").
     * @param key String which contains ID, for example it can be a MAC address.
     * @return Instance index on success and 0 otherwise.
     */
    uint32_t get_instance_index(const std::string &specific_path, const std::string &key) override;

    /**
     * @brief Get Date and Time in the Ambiorix data model format: "2020-08-31T11:22:39Z".
     *
     * @return String with date and time in the Ambiorix data model format.
     */
    std::string get_datamodel_time_format() override;

    /**
     * @brief Remove all instances from the data model object which name starts with given relative path
     *
     * @param relative_path Path to the object with type list in datamodel (ex: "Controller.Network.Device").
     * @return True on success and false otherwise.
     */
    bool remove_all_instances(const std::string &relative_path) override;

    /**
     * @brief Instantiate optional sub-object.
     *
     * The subobject must be defined as a mib in the odl file. The name of the mib must be the same as
     * the name of the subobject, and it must contain only a single object definition.
     *
     * @param path_to_obj path to the object in datamodel (ex: "Controller.Network").
     * @param subobject_name name of optional subobject to instantiate (ex: "HTCapabilities").
     * @return true if subobject successfully added, false otherwise
     */
    bool add_optional_subobject(const std::string &path_to_obj,
                                const std::string &subobject_name) override;

    /**
     * @brief Remove optional sub-object.
     *
     * The subobject must be defined as a mib in the odl file. The name of the mib must be the same as
     * the name of the subobject, and it must contain only a single object definition.
     *
     * @param path_to_obj path to the object in datamodel (ex: "Controller.Network").
     * @param subobject_name name of optional subobject to be removed (ex: "HTCapabilities").
     * @return true if subobject successfully removed, false otherwise
     */
    bool remove_optional_subobject(const std::string &path_to_obj,
                                   const std::string &subobject_name) override;

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
};

} // namespace nbapi
} // namespace beerocks

#endif
