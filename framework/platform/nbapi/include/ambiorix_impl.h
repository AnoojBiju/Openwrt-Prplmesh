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

#include "ambiorix.h"
#include "ambiorix_amxc.h"
#include "ambiorix_config.h"
#include "../ambiorixstorage.h"

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
 * TYPE
 */
typedef enum _pcm_type {
    pcm_type_upc = 0,                                       /**< UPC type */
    pcm_type_usersetting                                    /**< UserSetting type */
} pcm_type_t;
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *_pcm_type_str(_pcm_type enum_value) {
    switch (enum_value) {
    case pcm_type_upc:         return "pcm_type_upc";
    case pcm_type_usersetting: return "pcm_type_usersetting";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, _pcm_type value) { return out << _pcm_type_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end
#define pcm_type_max            (pcm_type_usersetting + 1)  /**< Number of types */

/**
 * @class AmbiorixImpl
 * @brief This class manages the ambiorixImpl instance.
 */
class AmbiorixImpl : public Ambiorix, AmbiorixOdlManager{

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
             const int8_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int16_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int32_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int64_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint8_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint16_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint32_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint64_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const bool &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const double &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const sMacAddr &value) override;

    std::string add_instance(const std::string &relative_path) override;

    bool remove_instance(const std::string &relative_path, uint32_t index) override;

    uint32_t get_instance_index(const std::string &specific_path, const std::string &key) override;

    std::string get_datamodel_time_format() override;

    /**
     * @brief Set current data and time in RFC 3339 format.
     *
     * @param path_to_object Path to NBAPI object which has parameter object.
     * @param param parameter name which is default as TimeStamp.
     * @return True if date and time successfully set, false otherwise.
     */
    bool set_current_time(const std::string &path_to_object,
                          const std::string &param = "TimeStamp") override;

    /**
     * @brief Set field 'TimeStamp'  in RFC 3339 format.
     *
     * @param path_to_object Path to NBAPI object which has parameter object 'TimeStamp'
     * @param param time_stamp specific time_stamp.
     * @return True if date and time successfully set, false otherwise.
     */
    bool set_time(const std::string &path_to_object, const std::string &time_stamp) override;

    bool remove_all_instances(const std::string &relative_path) override;

    bool add_optional_subobject(const std::string &path_to_obj,
                                const std::string &subobject_name) override;

    bool remove_optional_subobject(const std::string &path_to_obj,
                                   const std::string &subobject_name) override;

    /**
     * @brief Reads and return from Data Model value of uint64 parameter for given object.
     * 
     * @param[in] obj_path Path to object.
     * @param[in] param_name Name of the parametr.
     * @param[out] param_val Value of parameter.
     * @return True on success, false otherwise.
    */
    bool read_param(const std::string &obj_path, const std::string &param_name,
                    uint64_t *param_val) override;

    bool read_param(const std::string &obj_path, const std::string &param_name,
                    std::string *param_val) override;

private:
    // Methods

    void pcm_svc_param_changed(const char* const sig_name,
                                             const amxc_var_t* const data,
                                             void* const priv);
    bool pcm_svc_has_upc_params(amxd_object_t* object, pcm_type_t type);

    //runtime handlers

    /**
     * @brief Prepare transaction to the ubus
     *
     * @param relative_path Path to the object in datamodel (ex: "Device.WiFi.DataElements.Network.ID").
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
    bool load_datamodel();

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
     * @param relative_path Path to the object in datamodel (ex: "Device.WiFi.DataElements.Network.ID").
     * @return Pointer on the object on success and nullptr otherwise.
     */
    amxd_object_t *find_object(const std::string &relative_path);

    // Variables
    amxb_bus_ctx_t *m_bus_ctx = nullptr;
    std::shared_ptr<EventLoop> m_event_loop;
    //std::unordered_map<std::string, actions_callback> m_on_action_handlers;
    std::vector<sActionsCallback> m_on_action_handlers;
    std::vector<sEvents> m_events_list;
    std::vector<sFunctions> m_func_list;

};

} // namespace nbapi
} // namespace beerocks

#endif
