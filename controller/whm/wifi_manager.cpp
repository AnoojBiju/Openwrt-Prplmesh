/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "wifi_manager.h"

#include <beerocks/tlvf/beerocks_message_bml.h>
#include <bpl/bpl_cfg.h>

#include <regex>
#include <string>

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace prplmesh {
namespace controller {
namespace whm {

WifiManager::WifiManager(std::shared_ptr<beerocks::EventLoop> event_loop, son::db *ctx_wifi_db)
{

    m_event_loop  = event_loop;
    m_ctx_wifi_db = ctx_wifi_db;

    m_ambiorix_cl = std::make_shared<beerocks::wbapi::AmbiorixClient>();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client object!";

    LOG_IF(!m_ambiorix_cl->connect(AMBIORIX_WBAPI_BACKEND_PATH, AMBIORIX_WBAPI_BUS_URI), FATAL)
        << "Unable to connect to the ambiorix backend!";

    m_ambiorix_cl->init_event_loop(m_event_loop);
    m_ambiorix_cl->init_signal_loop(m_event_loop);
}

bool WifiManager::bss_info_config_change()
{

    m_ctx_wifi_db->clear_bss_info_configuration();

    std::list<son::wireless_utils::sBssInfoConf> wireless_settings;
    if (beerocks::bpl::bpl_cfg_get_wireless_settings(wireless_settings)) {
        for (const auto &configuration : wireless_settings) {
            m_ctx_wifi_db->add_bss_info_configuration(configuration);
        }
    } else {
        LOG(DEBUG) << "failed to read wireless settings";
        return false;
    }

    // Update wifi credentials
    uint8_t m_tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(m_tx_buffer, sizeof(m_tx_buffer));
    auto connected_agents = m_ctx_wifi_db->get_all_connected_agents();

    if (!connected_agents.empty()) {
        if (!son_actions::send_ap_config_renew_msg(cmdu_tx, *m_ctx_wifi_db)) {
            LOG(ERROR) << "Failed son_actions::send_ap_config_renew_msg ! ";
            return false;
        }
    }
    return true;
}

void WifiManager::subscribe_to_bss_info_config_change()
{
    std::string wifi_path               = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER;
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = AMX_CL_OBJECT_CHANGED_EVT;
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        amxc_var_t *params = GET_ARG(event_data, "parameters");
        const char *path   = GET_CHAR(event_data, "path");
        if (!path) {
            return;
        }
        bool config_changed = false;
        amxc_var_for_each(param, params)
        {
            const char *key = amxc_var_key(param);
            if (!key) {
                continue;
            }

            auto const radio_path_regex =
                std::regex(std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                           std::string(AMX_CL_RADIO_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + "*" +
                           AMX_CL_OBJ_DELIMITER);

            auto const ssid_path_regex =
                std::regex(std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                           std::string(AMX_CL_SSID_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + "*" +
                           AMX_CL_OBJ_DELIMITER);

            auto const security_path_regex =
                std::regex(std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                           std::string(AMX_CL_SSID_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + "*" +
                           +"Security" + AMX_CL_OBJ_DELIMITER);

            if (std::regex_search(path, radio_path_regex)) {
                if ((std::string(key) == "OperatingClass") || (std::string(key) == "Channel") ||
                    (std::string(key) == "AP_Mode") || (std::string(key) == "MultiAPType")) {
                    config_changed = true;
                }
            } else if (std::regex_search(path, ssid_path_regex)) {
                if ((std::string(key) == "SSID")) {
                    config_changed = true;
                }
            } else if (std::regex_search(path, security_path_regex)) {
                if ((std::string(key) == "ModeEnabled") || (std::string(key) == "EncryptionMode") ||
                    (std::string(key) == "KeyPassPhrase")) {
                    config_changed = true;
                }
            }
        }
        if (config_changed) {
            (static_cast<WifiManager *>(context))->bss_info_config_change();
        }
    };
    event_callback->context = this;
    m_ambiorix_cl->subscribe_to_object_event(wifi_path, nullptr, event_callback);
}

WifiManager::~WifiManager()
{
    m_ambiorix_cl->remove_event_loop(m_event_loop);
    m_ambiorix_cl->remove_signal_loop(m_event_loop);
}

} // namespace whm
} // namespace controller
} // namespace prplmesh
