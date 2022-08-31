/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "controller_connectivity_task.h"

#include "../agent_db.h"
#include "../son_slave_thread.h"

#include <tlvf/wfa_map/tlvHigherLayerData.h>

#include <easylogging++.h>

using namespace beerocks;
using namespace net;

static constexpr std::chrono::seconds HEARTBEAT_SENDING_PERIOD_SEC{2};
static constexpr uint8_t MAX_HEARTBEAT_COUNT{3};
static constexpr uint8_t INDIRECT_TIMEOUT_MULTIPLIER{3};

#define FSM_IS_IN_STATE(state) (m_task_state == eState::state)
#define FSM_MOVE_STATE(new_state)                                                                  \
    ({                                                                                             \
        LOG(TRACE) << "CONTROLLER_CONNECTIVITY "                                                   \
                   << " FSM: " << fsm_state_to_string(m_task_state) << " --> "                     \
                   << fsm_state_to_string(eState::new_state);                                      \
        m_task_state = eState::new_state;                                                          \
    })

const std::string ControllerConnectivityTask::fsm_state_to_string(eState status)
{
    switch (status) {
    case eState::INIT:
        return "INIT";
    case eState::WAIT_FOR_CONTROLLER_DISCOVERY:
        return "WAIT_FOR_CONTROLLER_DISCOVERY";
    case eState::CONTROLLER_MONITORING:
        return "CONTROLLER_MONITORING";
    case eState::WAIT_RESPONSE_FROM_CONTROLLER:
        return "WAIT_RESPONSE_FROM_CONTROLLER";
    case eState::CONNECTION_TIMEOUT:
        return "CONNECTION_TIMEOUT";
    case eState::BACKHAUL_LINK_DISCONNECTED:
        return "BACKHAUL_LINK_DISCONNECTED";
    default:
        LOG(ERROR) << "state argument doesn't have an enum";
        break;
    }
    return std::string();
}

ControllerConnectivityTask::ControllerConnectivityTask(slave_thread &btl_ctx,
                                                       ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CONTROLLER_CONNECTIVITY), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

void ControllerConnectivityTask::work()
{
    if (!m_task_is_active) {
        return;
    }

    switch (m_task_state) {
    case eState::INIT: {
        // TODO: Add new search/initialization mechanism to attach previously stored BH credentials (PPM-2281)
        break;
    }
    case eState::WAIT_FOR_CONTROLLER_DISCOVERY: {
        check_backhaul_connection_time();
        break;
    }
    case eState::CONTROLLER_MONITORING: {

        // If indirect checking is disabled, don't check connectivity when there is indirect link
        auto db = AgentDB::get();
        if (m_direct_link_to_controller ||
            db->device_conf.check_indirect_connectivity_to_controller) {
            check_controller_last_contact_time();
        }
        break;
    }
    case eState::WAIT_RESPONSE_FROM_CONTROLLER: {
        check_controller_last_contact_time();
        if (FSM_IS_IN_STATE(WAIT_RESPONSE_FROM_CONTROLLER)) {
            check_last_heartbeat_time();
        }
        break;
    }
    case eState::CONNECTION_TIMEOUT: {
        // TODO: Change to RECONNECTION state and search other possible links (PPM-2282)
        send_disconnect_to_backhaul_manager();
        FSM_MOVE_STATE(BACKHAUL_LINK_DISCONNECTED);
        break;
    }
    case eState::BACKHAUL_LINK_DISCONNECTED: {
        break;
    }
    default:
        break;
    }
}

void ControllerConnectivityTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    case INIT_TASK: {
        init_task_configuration();
        LOG(DEBUG) << "INIT_TASK is received and task activity: " << m_task_is_active;
        break;
    }
    case BACKHAUL_MANAGER_CONNECTED: {
        LOG(DEBUG) << "BACKHAUL_MANAGER_CONNECTED is received";

        // Each time backhaul manager makes a new connection, assume that we do not have direct link to Controller.
        // It will be updated after, we start listening to Discovery messages.
        auto db                                       = AgentDB::get();
        m_direct_link_to_controller                   = false;
        db->controller_info.direct_link_to_controller = false;
        m_backhaul_connected_time                     = std::chrono::steady_clock::now();
        FSM_MOVE_STATE(WAIT_FOR_CONTROLLER_DISCOVERY);
        break;
    }
    case BACKHAUL_DISCONNECTED_NOTIFICATION: {
        LOG(DEBUG) << "BACKHAUL_DISCONNECTED_NOTIFICATION is received";
        FSM_MOVE_STATE(BACKHAUL_LINK_DISCONNECTED);
        break;
    }
    case CONTROLLER_DISCOVERED: {
        LOG(DEBUG) << "CONTROLLER_DISCOVERED is received";
        FSM_MOVE_STATE(CONTROLLER_MONITORING);
        break;
    }
    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ControllerConnectivityTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                             uint32_t iface_index, const sMacAddr &dst_mac,
                                             const sMacAddr &src_mac, int fd,
                                             std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::TOPOLOGY_DISCOVERY_MESSAGE: {

        // We expect discovery messages from Controller after it is discovered.
        if (FSM_IS_IN_STATE(CONTROLLER_MONITORING)) {
            auto db = AgentDB::get();
            if (src_mac == db->controller_info.bridge_mac) {
                LOG_IF(!m_direct_link_to_controller, INFO) << "Agent has direct link to Controller";
                m_direct_link_to_controller = true;
            }
        }

        // Return false so another task will handle this message
        return false;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
}

void ControllerConnectivityTask::check_controller_last_contact_time()
{
    auto db               = AgentDB::get();
    auto time_elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - db->controller_info.last_controller_contact_time);

    auto message_timeout_sec    = db->device_conf.controller_message_timeout_seconds;
    auto connection_timeout_sec = db->device_conf.controller_message_timeout_seconds +
                                  db->device_conf.controller_heartbeat_state_timeout_seconds;

    // Incase of indirect connection, multiple timeout periods
    if (!m_direct_link_to_controller) {
        message_timeout_sec *= INDIRECT_TIMEOUT_MULTIPLIER;
        connection_timeout_sec *= INDIRECT_TIMEOUT_MULTIPLIER;
    }

    // Heartbeat parameters should be cleared only once, so state is checked as "CONTROLLER_MONITORING".
    if (FSM_IS_IN_STATE(CONTROLLER_MONITORING) && time_elapsed_sec > message_timeout_sec) {
        clear_heartbeat_counters();
        FSM_MOVE_STATE(WAIT_RESPONSE_FROM_CONTROLLER);
    } else if (time_elapsed_sec > connection_timeout_sec) {
        FSM_MOVE_STATE(CONNECTION_TIMEOUT);
    }
}

void ControllerConnectivityTask::check_last_heartbeat_time()
{
    auto time_elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_last_heartbeat_send_time);

    if (m_count_heartbeat_message < MAX_HEARTBEAT_COUNT &&
        time_elapsed_sec > HEARTBEAT_SENDING_PERIOD_SEC) {

        // Higher Layer Data should be replied in one second according to standard, so it is used as heartbeat.
        send_hle_to_controller();
        m_count_heartbeat_message++;
        m_last_heartbeat_send_time = std::chrono::steady_clock::now();

        LOG(DEBUG) << "Sending heartbeat to Controller with HLE for " << m_count_heartbeat_message
                   << " times";
    }
}

void ControllerConnectivityTask::check_backhaul_connection_time()
{
    auto db               = AgentDB::get();
    auto time_elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_backhaul_connected_time);

    if (time_elapsed_sec > db->device_conf.backhaul_connection_timeout_seconds) {
        LOG(DEBUG) << "Backhaul link does not provide Controller connectivity";
        FSM_MOVE_STATE(CONNECTION_TIMEOUT);
    }
}

void ControllerConnectivityTask::clear_heartbeat_counters()
{
    m_count_heartbeat_message  = 0;
    m_last_heartbeat_send_time = std::chrono::steady_clock::now();
}

bool ControllerConnectivityTask::send_hle_to_controller()
{
    auto cmdu_tx_header = m_cmdu_tx.create(0, ieee1905_1::eMessageType::HIGHER_LAYER_DATA_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "Failed to create ieee1905_1::eMessageType::HIGHER_LAYER_DATA_MESSAGE";
        return false;
    }

    auto tlvHigherLayerData = m_cmdu_tx.addClass<wfa_map::tlvHigherLayerData>();
    if (!tlvHigherLayerData) {
        LOG(ERROR) << "addClass wfa_map::tlvHigherLayerData failed";
        return false;
    }
    return m_btl_ctx.send_cmdu_to_controller({}, m_cmdu_tx);
}

bool ControllerConnectivityTask::send_disconnect_to_backhaul_manager()
{
    auto bh_disconnect_cmd =
        message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_DISCONNECT_COMMAND>(
            m_cmdu_tx);
    if (bh_disconnect_cmd == nullptr) {
        LOG(ERROR) << "Failed building message ACTION_BACKHAUL_DISCONNECT_COMMAND!";
        return false;
    }
    auto backhaul_manager_cmdu_client = m_btl_ctx.get_backhaul_manager_cmdu_client();
    if (!backhaul_manager_cmdu_client) {
        LOG(ERROR) << "Failed to get backhaul manager cmdu client";
        return false;
    }
    return backhaul_manager_cmdu_client->send_cmdu(m_cmdu_tx);
}

void ControllerConnectivityTask::init_task_configuration()
{
    // Local Controller's agent does not need to check backhaul connectivity
    // To prevent certification procedures, it is bypassed.
    auto db = AgentDB::get();
    if (db->device_conf.certification_mode || !db->device_conf.check_connectivity_to_controller) {
        m_task_is_active = false;
        return;
    }
    m_task_is_active = true;
}
