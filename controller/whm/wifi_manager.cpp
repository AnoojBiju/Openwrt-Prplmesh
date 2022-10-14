/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "wifi_manager.h"

#include "ambiorix_client_factory.h"

#include <beerocks/tlvf/beerocks_message_bml.h>
#include <bpl/bpl_cfg.h>

#include <regex>
#include <string>

using namespace beerocks;
using namespace wbapi;

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

    m_ambiorix_cl = AmbiorixClientFactory::create_instance();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client object!";

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
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = AMX_CL_OBJECT_CHANGED_EVT;
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        (static_cast<WifiManager *>(context))->bss_info_config_change();
    };
    event_callback->context = this;

    std::string filter = "path matches '" + wbapi_utils::search_path_radio() + "[0-9]+.'";
    filter.append(" && (contains('parameters.OperatingClass') || contains('parameters.Channel')"
                  " || contains('parameters.AP_Mode') || contains('parameters.MultiAPType'))");
    m_ambiorix_cl->subscribe_to_object_event(wbapi_utils::search_path_radio(), event_callback);

    filter = "path matches '" + wbapi_utils::search_path_ssid() + "[0-9]+.'";
    filter.append(" && contains('parameters.SSID')");
    m_ambiorix_cl->subscribe_to_object_event(wbapi_utils::search_path_ssid(), event_callback);

    filter = "path matches '" + wbapi_utils::search_path_ap() + "[0-9]+.Security.'";
    filter.append(" && (contains('parameters.ModeEnabled') || contains('parameters.EncryptionMode')"
                  " || contains('parameters.KeyPassPhrase'))");
    m_ambiorix_cl->subscribe_to_object_event(wbapi_utils::search_path_ap(), event_callback);
}

WifiManager::~WifiManager()
{
    m_ambiorix_cl->remove_event_loop(m_event_loop);
    m_ambiorix_cl->remove_signal_loop(m_event_loop);
}

} // namespace whm
} // namespace controller
} // namespace prplmesh
