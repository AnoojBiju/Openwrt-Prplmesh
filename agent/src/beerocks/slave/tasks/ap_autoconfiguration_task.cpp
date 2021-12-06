/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "ap_autoconfiguration_task.h"

#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager.h"

#include <tlvf/ieee_1905_1/tlvAlMacAddress.h>
#include <tlvf/ieee_1905_1/tlvAutoconfigFreqBand.h>
#include <tlvf/ieee_1905_1/tlvSearchedRole.h>
#include <tlvf/ieee_1905_1/tlvSupportedFreqBand.h>
#include <tlvf/ieee_1905_1/tlvSupportedRole.h>
#include <tlvf/wfa_map/tlvProfile2MultiApProfile.h>
#include <tlvf/wfa_map/tlvSearchedService.h>
#include <tlvf/wfa_map/tlvSupportedService.h>

#include <beerocks/tlvf/beerocks_message_control.h>

#include <easylogging++.h>

using namespace beerocks;
using namespace net;
using namespace son;

static constexpr uint8_t AUTOCONFIG_DISCOVERY_TIMEOUT_SECONDS = 3;

#define FSM_MOVE_STATE(radio_iface, new_state)                                                     \
    ({                                                                                             \
        LOG(TRACE) << "AP_AUTOCONFIGURATION " << radio_iface                                       \
                   << " FSM: " << fsm_state_to_string(m_radios_conf_params[radio_iface].state)     \
                   << " --> " << fsm_state_to_string(new_state);                                   \
        m_radios_conf_params[radio_iface].state = new_state;                                       \
    })

const std::string ApAutoConfigurationTask::fsm_state_to_string(eState status)
{
    switch (status) {
    case eState::UNCONFIGURED:
        return "UNCONFIGURED";
    case eState::CONTROLLER_DISCOVERY:
        return "CONTROLLER_DISCOVERY";
    case eState::WAIT_FOR_CONTROLLER_DISCOVERY_COMPLETE:
        return "WAIT_FOR_CONTROLLER_DISCOVERY_COMPLETE";
    case eState::SEND_AP_AUTOCONFIGURATION_WSC_M1:
        return "SEND_AP_AUTOCONFIGURATION_WSC_M1";
    case eState::WAIT_AP_AUTOCONFIGURATION_WSC_M2:
        return "WAIT_AP_AUTOCONFIGURATION_WSC_M2";
    case eState::CONFIGIRED:
        return "CONFIGIRED";
    default:
        LOG(ERROR) << "state argument doesn't have an enum";
        break;
    }
    return std::string();
}

ApAutoConfigurationTask::ApAutoConfigurationTask(slave_thread &btl_ctx,
                                                 ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::AP_AUTOCONFIGURATION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ApAutoConfigurationTask::work()
{
    if (!m_task_is_active) {
        return;
    }

    uint8_t configured_aps_count = 0;
    for (auto &radios_conf_param_kv : m_radios_conf_params) {
        const auto &radio_iface = radios_conf_param_kv.first;
        auto &conf_params       = radios_conf_param_kv.second;
        switch (conf_params.state) {
        case eState::UNCONFIGURED: {
            break;
        }
        case eState::CONTROLLER_DISCOVERY: {
            auto db = AgentDB::get();

            auto radio = db->radio(radio_iface);
            if (!radio) {
                continue;
            }

            // If another radio with same band already finished the discovery phase, we can skip
            // directly to next phase (AP_CONFIGURATION).
            if (m_discovery_status[radio->freq_type].completed) {
                FSM_MOVE_STATE(radio_iface, eState::SEND_AP_AUTOCONFIGURATION_WSC_M1);
            }

            // If another radio with same band already have sent the
            // AP_AUTOCONFIGURATION_SEARCH_MESSAGE, we can skip and let it handle it.
            if (m_discovery_status[radio->freq_type].msg_sent) {
                continue;
            }

            if (send_ap_autoconfiguration_search_message(radio_iface)) {
                m_discovery_status[radio->freq_type].msg_sent = true;
            }

            conf_params.timeout = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(AUTOCONFIG_DISCOVERY_TIMEOUT_SECONDS);

            FSM_MOVE_STATE(radio_iface, eState::WAIT_FOR_CONTROLLER_DISCOVERY_COMPLETE);
            break;
        }
        case eState::WAIT_FOR_CONTROLLER_DISCOVERY_COMPLETE: {
            auto db    = AgentDB::get();
            auto radio = db->radio(radio_iface);
            if (!radio) {
                continue;
            }
            if (m_discovery_status[radio->freq_type].completed) {
                FSM_MOVE_STATE(radio_iface, eState::SEND_AP_AUTOCONFIGURATION_WSC_M1);
                break;
            }

            if (std::chrono::steady_clock::now() > conf_params.timeout) {
                FSM_MOVE_STATE(radio_iface, eState::CONTROLLER_DISCOVERY);
                m_discovery_status[radio->freq_type].msg_sent = false;
            }
            break;
        }
        case eState::SEND_AP_AUTOCONFIGURATION_WSC_M1: {
            FSM_MOVE_STATE(radio_iface, eState::WAIT_AP_AUTOCONFIGURATION_WSC_M2);
            break;
        }
        case eState::WAIT_AP_AUTOCONFIGURATION_WSC_M2: {
            break;
        }
        case eState::CONFIGIRED: {
            configured_aps_count++;
            break;
        }
        default:
            break;
        }
    }

    // Update status on the database.
    auto db = AgentDB::get();
    if (configured_aps_count > 0 && configured_aps_count == m_radios_conf_params.size()) {
        db->statuses.ap_autoconfiguration_completed = true;
        m_task_is_active                            = false;
    }
}

void ApAutoConfigurationTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    case INIT_TASK: {
        auto db = AgentDB::get();

        db->statuses.ap_autoconfiguration_completed = false;

        // Reset the discovery statuses.
        for (auto &discovery_status : m_discovery_status) {
            discovery_status.second = {};
        }
        m_task_is_active = false;
        break;
    }
    case START_AP_AUTOCONFIGURATION: {
        auto db = AgentDB::get();
        for (const auto radio : db->get_radios_list()) {
            if (!radio) {
                continue;
            }

            if (event_obj) {
                auto specific_iface_ptr = reinterpret_cast<const std::string *>(event_obj);
                if (*specific_iface_ptr != radio->front.iface_name) {
                    continue;
                }
            }

            LOG(DEBUG) << "starting discovery sequence on radio_iface=" << radio->front.iface_name;
            FSM_MOVE_STATE(radio->front.iface_name, eState::CONTROLLER_DISCOVERY);
            m_task_is_active = true;
        }
        // Call work() to not waste time, and send_ap_autoconfiguration_search_message immediately.
        work();
        break;
    }
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ApAutoConfigurationTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                                          const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                                          std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_RESPONSE_MESSAGE: {
        handle_ap_autoconfiguration_response(cmdu_rx, src_mac);
        return true;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
}

bool ApAutoConfigurationTask::send_ap_autoconfiguration_search_message(
    const std::string &radio_iface)
{
    auto db = AgentDB::get();

    ieee1905_1::tlvAutoconfigFreqBand::eValue freq_band =
        ieee1905_1::tlvAutoconfigFreqBand::IEEE_802_11_2_4_GHZ;
    /*
     * TODO
     * this is a workaround, need to find a better way to know each slave's band
     */
    auto radio = db->radio(radio_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of iface " << radio_iface << " does not exist on the db";
        return false;
    }
    if (radio->freq_type == beerocks::eFreqType::FREQ_24G) {
        freq_band = ieee1905_1::tlvAutoconfigFreqBand::IEEE_802_11_2_4_GHZ;
    } else if (radio->freq_type == beerocks::eFreqType::FREQ_5G) {
        freq_band = ieee1905_1::tlvAutoconfigFreqBand::IEEE_802_11_5_GHZ;
    } else {
        LOG(ERROR) << "unsupported freq_type=" << int(radio->freq_type)
                   << ", iface=" << radio_iface;
        return false;
    }

    auto create_autoconfig_search = [&]() -> bool {
        auto cmdu_header =
            m_cmdu_tx.create(0, ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_SEARCH_MESSAGE);
        if (!cmdu_header) {
            LOG(ERROR) << "cmdu creation of type AP_AUTOCONFIGURATION_SEARCH_MESSAGE, has failed";
            return false;
        }

        auto tlvAlMacAddress = m_cmdu_tx.addClass<ieee1905_1::tlvAlMacAddress>();
        if (!tlvAlMacAddress) {
            LOG(ERROR) << "addClass ieee1905_1::tlvAlMacAddress failed";
            return false;
        }
        tlvAlMacAddress->mac() = db->bridge.mac;

        auto tlvSearchedRole = m_cmdu_tx.addClass<ieee1905_1::tlvSearchedRole>();
        if (!tlvSearchedRole) {
            LOG(ERROR) << "addClass ieee1905_1::tlvSearchedRole failed";
            return false;
        }
        tlvSearchedRole->value() = ieee1905_1::tlvSearchedRole::REGISTRAR;

        auto tlvAutoconfigFreqBand = m_cmdu_tx.addClass<ieee1905_1::tlvAutoconfigFreqBand>();
        if (!tlvAutoconfigFreqBand) {
            LOG(ERROR) << "addClass ieee1905_1::tlvAutoconfigFreqBand failed";
            return false;
        }
        tlvAutoconfigFreqBand->value() = freq_band;

        auto tlvSupportedService = m_cmdu_tx.addClass<wfa_map::tlvSupportedService>();
        if (!tlvSupportedService) {
            LOG(ERROR) << "addClass wfa_map::tlvSupportedService failed";
            return false;
        }
        if (!tlvSupportedService->alloc_supported_service_list()) {
            LOG(ERROR) << "alloc_supported_service_list failed";
            return false;
        }
        auto supportedServiceTuple = tlvSupportedService->supported_service_list(0);
        if (!std::get<0>(supportedServiceTuple)) {
            LOG(ERROR) << "Failed accessing supported_service_list";
            return false;
        }
        std::get<1>(supportedServiceTuple) =
            wfa_map::tlvSupportedService::eSupportedService::MULTI_AP_AGENT;

        auto tlvSearchedService = m_cmdu_tx.addClass<wfa_map::tlvSearchedService>();
        if (!tlvSearchedService) {
            LOG(ERROR) << "addClass wfa_map::tlvSearchedService failed";
            return false;
        }
        if (!tlvSearchedService->alloc_searched_service_list()) {
            LOG(ERROR) << "alloc_searched_service_list failed";
            return false;
        }
        auto searchedServiceTuple = tlvSearchedService->searched_service_list(0);
        if (!std::get<0>(searchedServiceTuple)) {
            LOG(ERROR) << "Failed accessing searched_service_list";
            return false;
        }
        std::get<1>(searchedServiceTuple) =
            wfa_map::tlvSearchedService::eSearchedService::MULTI_AP_CONTROLLER;

        // Add prplMesh handshake in a vendor specific TLV.
        // If the controller is prplMesh, it will reply to the autoconfig search with
        // handshake response.
        auto request =
            message_com::add_vs_tlv<beerocks_message::cACTION_CONTROL_SLAVE_HANDSHAKE_REQUEST>(
                m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed adding cACTION_CONTROL_SLAVE_HANDSHAKE_REQUEST";
            return false;
        }
        auto beerocks_header                      = message_com::get_beerocks_header(m_cmdu_tx);
        beerocks_header->actionhdr()->direction() = beerocks::BEEROCKS_DIRECTION_CONTROLLER;
        LOG(DEBUG) << "sending autoconfig search message, bridge_mac=" << db->bridge.mac;
        return true;
    };

    create_autoconfig_search();
    if (db->controller_info.profile_support ==
        wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::MULTIAP_PROFILE_1) {
        return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, network_utils::MULTICAST_1905_MAC_ADDR,
                                             db->bridge.mac);
    } else if (db->controller_info.profile_support ==
               wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::PRPLMESH_PROFILE_UNKNOWN) {
        // If we still not know what profile the controller support send 2 autoconfig search messages:
        // one witout the MultiAp profile TLV and one with it.
        // We do this since we came across certified agents that don't respond to a search message that contain
        // the newly added TLV. So to make sure we will get a response send both options.
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, network_utils::MULTICAST_1905_MAC_ADDR,
                                      db->bridge.mac);
        create_autoconfig_search();
    }

    auto tlvProfile2MultiApProfile = m_cmdu_tx.addClass<wfa_map::tlvProfile2MultiApProfile>();
    if (!tlvProfile2MultiApProfile) {
        LOG(ERROR) << "addClass wfa_map::tlvProfile2MultiApProfile failed";
        return false;
    }
    LOG(DEBUG) << "sending autoconfig search message, bridge_mac=" << db->bridge.mac
               << " with Profile TLV";

    return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, network_utils::MULTICAST_1905_MAC_ADDR,
                                         db->bridge.mac);
}

void ApAutoConfigurationTask::handle_ap_autoconfiguration_response(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    LOG(DEBUG) << "Received autoconfiguration response message";
    auto db = AgentDB::get();
    if (db->controller_info.bridge_mac != network_utils::ZERO_MAC &&
        src_mac != db->controller_info.bridge_mac) {
        LOG(INFO) << "current controller_bridge_mac=" << db->controller_info.bridge_mac
                  << " but response came from src_mac=" << src_mac << ", ignoring";
        return;
    }

    auto tlvSupportedRole = cmdu_rx.getClass<ieee1905_1::tlvSupportedRole>();
    if (!tlvSupportedRole) {
        LOG(ERROR) << "getClass tlvSupportedRole failed";
        return;
    }

    if (tlvSupportedRole->value() != ieee1905_1::tlvSupportedRole::REGISTRAR) {
        LOG(ERROR) << "invalid tlvSupportedRole value";
        return;
    }

    // Set prplmesh_controller to false by default. If "SLAVE_HANDSHAKE_RESPONSE" is received, mark
    // it to 'true'.
    bool prplmesh_controller = false;

    auto beerocks_header = message_com::parse_intel_vs_message(cmdu_rx);
    if (beerocks_header &&
        beerocks_header->action_op() == beerocks_message::ACTION_CONTROL_SLAVE_HANDSHAKE_RESPONSE) {
        // Mark controller as prplMesh.
        LOG(DEBUG) << "prplMesh controller: received ACTION_CONTROL_SLAVE_HANDSHAKE_RESPONSE from "
                   << src_mac;
        prplmesh_controller = true;
    } else {
        LOG(DEBUG) << "Not prplMesh controller " << src_mac;
    }

    auto tlvSupportedFreqBand = cmdu_rx.getClass<ieee1905_1::tlvSupportedFreqBand>();
    if (!tlvSupportedFreqBand) {
        LOG(ERROR) << "getClass tlvSupportedFreqBand failed";
        return;
    }

    std::string band_name;
    beerocks::eFreqType freq_type = beerocks::eFreqType::FREQ_UNKNOWN;
    switch (tlvSupportedFreqBand->value()) {
    case ieee1905_1::tlvSupportedFreqBand::BAND_2_4G:
        band_name = "2.4GHz";
        freq_type = beerocks::eFreqType::FREQ_24G;
        break;
    case ieee1905_1::tlvSupportedFreqBand::BAND_5G:
        band_name = "5GHz";
        freq_type = beerocks::eFreqType::FREQ_5G;
        break;
    case ieee1905_1::tlvSupportedFreqBand::BAND_60G:
        LOG(DEBUG) << "received autoconfiguration response for 60GHz band, unsupported";
        return;
    default:
        LOG(ERROR) << "invalid tlvSupportedFreqBand value";
        return;
    }
    LOG(DEBUG) << "received ap_autoconfiguration response for " << band_name << " band";

    auto tlvSupportedService = cmdu_rx.getClass<wfa_map::tlvSupportedService>();
    if (!tlvSupportedService) {
        LOG(ERROR) << "getClass tlvSupportedService failed";
        return;
    }
    bool controller_found = false;
    for (int i = 0; i < tlvSupportedService->supported_service_list_length(); i++) {
        auto supportedServiceTuple = tlvSupportedService->supported_service_list(i);
        if (!std::get<0>(supportedServiceTuple)) {
            LOG(ERROR) << "Invalid tlvSupportedService";
            return;
        }
        if (std::get<1>(supportedServiceTuple) ==
            wfa_map::tlvSupportedService::eSupportedService::MULTI_AP_CONTROLLER) {
            controller_found = true;
        }
    }

    if (!controller_found) {
        LOG(WARNING)
            << "Invalid tlvSupportedService - supported service is not MULTI_AP_CONTROLLER";
        return;
    }

    auto multiap_profile_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2MultiApProfile>();
    if (multiap_profile_tlv) {
        db->controller_info.profile_support = multiap_profile_tlv->profile();
    }

    // Mark discovery status completed on band mentioned on the response and fill AgentDB fields.
    db->controller_info.prplmesh_controller = prplmesh_controller;
    db->controller_info.bridge_mac          = src_mac;
    m_discovery_status[freq_type].completed = true;
    LOG(DEBUG) << "controller_discovered on " << band_name
               << " band, controller bridge_mac=" << src_mac
               << ", prplmesh_controller=" << prplmesh_controller;
}
