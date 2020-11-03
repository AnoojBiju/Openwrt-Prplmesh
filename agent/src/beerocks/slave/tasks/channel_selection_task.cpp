/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "channel_selection_task.h"
#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

#include <beerocks/tlvf/beerocks_message_backhaul.h>

#include <bcl/beerocks_utils.h>
#include <bcl/son/son_wireless_utils.h>

#define ZWDFS_FSM_MOVE_STATE(new_state)                                                            \
    ({                                                                                             \
        LOG(TRACE) << "CHANNEL_SELECTION ZWDFS FSM: " << m_zwdfs_states_string.at(m_zwdfs_state)   \
                   << " --> " << m_zwdfs_states_string.at(new_state);                              \
        m_zwdfs_state = new_state;                                                                 \
        zwdfs_fsm();                                                                               \
    })

namespace beerocks {

ChannelSelectionTask::ChannelSelectionTask(backhaul_manager &btl_ctx,
                                           ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SELECTION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
    // Initialize database members
    auto db                                   = AgentDB::get();
    db->statuses.zwdfs_cac_remaining_time_sec = 0;
}

void ChannelSelectionTask::work()
{
    if (zwdfs_in_process()) {
        zwdfs_fsm();
    }
}

bool ChannelSelectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                       Socket *sd, std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_REQUEST_MESSAGE: {
        handle_channel_selection_request(cmdu_rx, src_mac);
        // According to the WFA documentation, each radio should send channel selection
        // response even if that radio was not marked in the request. After filling radio
        // mac vector need to do forwarding for the channel selection request to all slaves.
        // In this scope return false forwards the message to the son_slave.
        return false;
    }
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE: {
        handle_slave_channel_selection_response(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::VENDOR_SPECIFIC_MESSAGE: {
        handle_vendor_specific(cmdu_rx, src_mac, sd, beerocks_header);
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void ChannelSelectionTask::handle_channel_selection_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                            const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    LOG(DEBUG) << "Forwarding CHANNEL_SELECTION_REQUEST to son_slave, mid=" << std::hex << mid;

    // Clear previous request, if any
    m_expected_channel_selection.requests.clear();
    m_expected_channel_selection.responses.clear();

    m_expected_channel_selection.mid = mid;

    auto db = AgentDB::get();

    // Save radio mac for each connected radio
    for (const auto radio : db->get_radios_list()) {
        m_expected_channel_selection.requests.emplace_back(radio->front.iface_mac);
    }
}

void ChannelSelectionTask::handle_slave_channel_selection_response(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received CHANNEL_SELECTION_RESPONSE message, mid=" << std::hex << mid;

    if (mid != m_expected_channel_selection.mid) {
        return;
    }

    auto channel_selection_response = cmdu_rx.getClass<wfa_map::tlvChannelSelectionResponse>();
    if (!channel_selection_response) {
        LOG(ERROR) << "Failed cmdu_rx.getClass<wfa_map::tlvChannelSelectionResponse>(), mid="
                   << std::hex << mid;
        return;
    }

    auto db = AgentDB::get();

    m_expected_channel_selection.responses.push_back(
        {channel_selection_response->radio_uid(), channel_selection_response->response_code()});

    // Remove an entry from the processed query
    m_expected_channel_selection.requests.erase(
        std::remove_if(m_expected_channel_selection.requests.begin(),
                       m_expected_channel_selection.requests.end(),
                       [&](sMacAddr const &query) {
                           return channel_selection_response->radio_uid() == query;
                       }),
        m_expected_channel_selection.requests.end());

    if (!m_expected_channel_selection.requests.empty()) {
        return;
    }

    // We received all responses - prepare and send response message to the controller
    auto cmdu_header =
        m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE);

    if (!cmdu_header) {
        LOG(ERROR) << "Failed building IEEE1905 CHANNEL_SELECTION_RESPONSE_MESSAGE";
        return;
    }

    for (const auto &response : m_expected_channel_selection.responses) {
        auto channel_selection_response_tlv =
            m_cmdu_tx.addClass<wfa_map::tlvChannelSelectionResponse>();

        if (!channel_selection_response_tlv) {
            LOG(ERROR) << "Failed addClass<wfa_map::tlvChannelSelectionResponse>";
            continue;
        }

        channel_selection_response_tlv->radio_uid()     = response.radio_mac;
        channel_selection_response_tlv->response_code() = response.response_code;
    }

    // Clear the m_expected_channel_selection.responses vector after preparing response to the controller
    m_expected_channel_selection.responses.clear();

    LOG(DEBUG) << "Sending CHANNEL_SELECTION_RESPONSE_MESSAGE, mid=" << std::hex << mid;
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(db->controller_info.bridge_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

bool ChannelSelectionTask::handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac, Socket *sd,
                                                  std::shared_ptr<beerocks_header> beerocks_header)
{
    if (!beerocks_header) {
        LOG(ERROR) << "beerocks_header is nullptr";
        return false;
    }

    // Since currently we handle only action_ops of action type "ACTION_BACKHAUL", use a single
    // switch-case on "ACTION_BACKHAUL" only.
    // Once the son_slave will be unified, need to replace the expected action to
    // "ACTION_AP_MANAGER". PPM-352.
    if (beerocks_header->action() == beerocks_message::ACTION_BACKHAUL) {
        switch (beerocks_header->action_op()) {
        case beerocks_message::ACTION_BACKHAUL_HOSTAP_CSA_NOTIFICATION: {
            handle_vs_csa_notification(cmdu_rx, sd, beerocks_header);
            break;
        }
        case beerocks_message::ACTION_BACKHAUL_HOSTAP_CSA_ERROR_NOTIFICATION: {
            handle_vs_csa_error_notification(cmdu_rx, sd, beerocks_header);
            break;
        }
        case beerocks_message::ACTION_BACKHAUL_HOSTAP_DFS_CAC_STARTED_NOTIFICATION: {
            handle_vs_cac_started_notification(cmdu_rx, sd, beerocks_header);
            break;
        }
        case beerocks_message::ACTION_BACKHAUL_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION: {
            handle_vs_dfs_cac_completed_notification(cmdu_rx, sd, beerocks_header);
            break;
        }
        case beerocks_message::ACTION_BACKHAUL_CHANNELS_LIST_RESPONSE: {
            handle_vs_channels_list_response(cmdu_rx, sd, beerocks_header);
            break;
        }
        case beerocks_message::ACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE: {
            handle_vs_zwdfs_ant_channel_switch_response(cmdu_rx, sd, beerocks_header);
            break;
        }

        default: {
            // Message was not handled, therfore return false.
            return false;
        }
        }
    }
    return true;
}

void ChannelSelectionTask::handle_vs_csa_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CSA_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION failed";
        return;
    }
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION from "
               << socket_to_front_iface_name(sd);

    auto db = AgentDB::get();

    auto sender_iface_name = socket_to_front_iface_name(sd);
    auto sender_radio      = db->radio(sender_iface_name);
    if (!sender_radio) {
        return;
    }

    // Initiate Agent Managed ZWDFS flow.
    if (db->device_conf.zwdfs_enable && !sender_radio->front.zwdfs &&
        notification->cs_params().switch_reason == beerocks::CH_SWITCH_REASON_RADAR &&
        m_zwdfs_state != eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED &&
        m_zwdfs_state != eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED) {

        if (!initialize_zwdfs_interface_name()) {
            LOG(DEBUG) << "No ZWDFS radio interface has been found. ZWDFS not initiated.";
            return;
        }
        m_zwdfs_primary_radio_iface = sender_radio->front.iface_name;
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
        return;
    }

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION &&
        sender_iface_name == m_zwdfs_primary_radio_iface) {
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
        return;
    }
}

void ChannelSelectionTask::handle_vs_csa_error_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header
            ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CSA_ERROR_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION failed";
        return;
    }
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CSA_ERROR_NOTIFICATION from "
               << socket_to_front_iface_name(sd);

    auto sender_iface_name = socket_to_front_iface_name(sd);
    std::string which_radio;
    if (zwdfs_in_process()) {
        if (sender_iface_name == m_zwdfs_iface) {
            which_radio = "ZWDFS";
        } else if (sender_iface_name == m_zwdfs_primary_radio_iface) {
            which_radio = "Primary 5G";
        }
        LOG(DEBUG) << "Failed to switch channel on " << which_radio << " radio, "
                   << sender_iface_name << ". Reset ZWDFS flow !";
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
    }
}

void ChannelSelectionTask::handle_vs_cac_started_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header
            ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_DFS_CAC_STARTED_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION failed";
        return;
    }
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION from "
               << socket_to_front_iface_name(sd);

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED) {
        auto db = AgentDB::get();
        // Set timeout for CAC-COMPLETED notification with the CAC duration received on this
        // this notification, multiplied in factor of 1.2.
        constexpr float CAC_DURATION_FACTOR = 1.2;
        auto cac_remaining_sec =
            uint16_t(notification->params().cac_duration_sec * CAC_DURATION_FACTOR);
        db->statuses.zwdfs_cac_remaining_time_sec = cac_remaining_sec;
        m_zwdfs_fsm_timeout =
            std::chrono::steady_clock::now() + std::chrono::seconds(cac_remaining_sec);
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED);
    }
}

void ChannelSelectionTask::handle_vs_dfs_cac_completed_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header
            ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION failed";
        return;
    }
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION from "
               << socket_to_front_iface_name(sd);

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED) {
        auto db                                   = AgentDB::get();
        db->statuses.zwdfs_cac_remaining_time_sec = 0;
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO);
    }
}

void ChannelSelectionTask::handle_vs_channels_list_response(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    LOG(TRACE) << "received ACTION_APMANAGER_CHANNELS_LIST_RESPONSE from "
               << socket_to_front_iface_name(sd);

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_CHANNELS_LIST) {
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::CHOOSE_NEXT_BEST_CHANNEL);
    }
}

void ChannelSelectionTask::handle_vs_zwdfs_ant_channel_switch_response(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification = beerocks_header->addClass<
        beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE>();
    if (!notification) {
        LOG(ERROR) << "addClass ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE failed";
        return;
    }
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE from "
               << socket_to_front_iface_name(sd);

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE) {
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
    }

    // Get here after switching on the ZWDFS antenna.
    if (!notification->success()) {
        LOG(ERROR) << "Failed to switch ZWDFS antenna and channel";
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
    }
}

const std::string ChannelSelectionTask::socket_to_front_iface_name(const Socket *sd)
{
    for (const auto &soc : m_btl_ctx.slaves_sockets) {
        if (soc->slave == sd) {
            return soc->hostap_iface;
        }
    }

    for (const auto &slave_element : m_btl_ctx.m_disabled_slave_sockets) {
        if (slave_element.second->slave == sd) {
            return slave_element.first;
        }
    }

    return std::string();
}
Socket *ChannelSelectionTask::front_iface_name_to_socket(const std::string &iface_name)
{
    for (const auto &soc : m_btl_ctx.slaves_sockets) {
        if (soc->hostap_iface == iface_name) {
            return soc->slave;
        }
    }
    for (const auto &slave_element : m_btl_ctx.m_disabled_slave_sockets) {
        if (slave_element.first == iface_name) {
            return slave_element.second->slave;
        }
    }
    return nullptr;
}

void ChannelSelectionTask::zwdfs_fsm()
{
    switch (m_zwdfs_state) {
    case eZwdfsState::NOT_RUNNING: {
        break;
    }
    case eZwdfsState::REQUEST_CHANNELS_LIST: {

        // Block the begining of the flow if background scan is running on one of the radios.
        // 2.4G because it is forbidden to switch zwdfs antenna during scan.
        // 5G because we don't want the ZWDFS flow will switch channel on the primary 5G radio
        // while it is during a background scan.
        auto db = AgentDB::get();
        auto break_state = false;
        for (const auto &radio : db->get_radios_list()) {
            if (!radio) {
                continue;
            }
            if (radio->statuses.dcs_background_scan_in_process) {
                break_state = true;
                break;
            }
        }
        if (break_state) {
            break;
        }

        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_REQUEST>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        auto fronthaul_sd = front_iface_name_to_socket(m_zwdfs_primary_radio_iface);
        if (!fronthaul_sd) {
            LOG(DEBUG) << "socket to fronthaul not found: " << m_zwdfs_primary_radio_iface;
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        message_com::send_cmdu(fronthaul_sd, m_cmdu_tx);

        constexpr uint8_t CHANNELS_LIST_RESPONSE_TIMEOUT_SEC = 1;

        m_zwdfs_fsm_timeout = std::chrono::steady_clock::now() +
                              std::chrono::seconds(CHANNELS_LIST_RESPONSE_TIMEOUT_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_CHANNELS_LIST);
        break;
    }
    case eZwdfsState::WAIT_FOR_CHANNELS_LIST: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for channels list response";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
        }
        break;
    }
    case eZwdfsState::CHOOSE_NEXT_BEST_CHANNEL: {
        m_selected_channel = zwdfs_select_best_usable_channel(m_zwdfs_primary_radio_iface);
        if (m_selected_channel.channel == 0) {
            LOG(ERROR) << "Error occurred on second best channel selection";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
        }

        auto db    = AgentDB::get();
        auto radio = db->radio(m_zwdfs_primary_radio_iface);
        if (!radio) {
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        if (m_selected_channel.channel == radio->channel &&
            m_selected_channel.bw == radio->bandwidth) {
            LOG(DEBUG) << "Failsafe is already second best channel, abort ZWDFS flow";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        LOG(DEBUG) << "Selected Channel=" << m_selected_channel.channel << " dfs_state=" << [&]() {
            if (m_selected_channel.dfs_state == beerocks_message::eDfsState::NOT_DFS) {
                return "NOT_DFS";
            } else if (m_selected_channel.dfs_state == beerocks_message::eDfsState::AVAILABLE) {
                return "AVAILABLE";
            } else if (m_selected_channel.dfs_state == beerocks_message::eDfsState::USABLE) {
                return "USABLE";
            }
            return "Unknown_State";
        }();

        // If the second best channel is not a DFS or Available, we can skip ZWDFS CAC, and
        //switch the channel immediately on the primary 5G radio.
        if (m_selected_channel.dfs_state == beerocks_message::eDfsState::NOT_DFS ||
            m_selected_channel.dfs_state == beerocks_message::eDfsState::AVAILABLE) {
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO);
            break;
        }

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST);
        break;
    }
    case eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST: {

        // Stop ZWDFS flow from doing CAC if a background scan has started before we switch the
        // ZWDFS antenna. Since at the time when the background scan will be over, the selected
        // channel might not be relevant anymore, the FSM will start over and jum to the initial
        // state which query the updated channel info from the AP.
        auto db = AgentDB::get();
        auto break_state = false;
        for (const auto &radio : db->get_radios_list()) {
            if (!radio) {
                continue;
            }
            if (radio->statuses.dcs_background_scan_in_process) {
                LOG(INFO) << "Pause ZWDFS flow until background scan on radio "
                          << radio->front.iface_name << " is finished";
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
                break_state = true;
                break;
            }
        }
        if (break_state) {
            break;
        }

        auto fronthaul_sd = front_iface_name_to_socket(m_zwdfs_iface);
        if (!fronthaul_sd) {
            LOG(DEBUG) << "socket to fronthaul not found: " << m_zwdfs_iface;
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        request->ant_switch_on() = true;
        request->channel()       = m_selected_channel.channel;
        request->bandwidth()     = m_selected_channel.bw;

        auto center_channel = son::wireless_utils::channels_table_5g.at(request->channel())
                                  .at(request->bandwidth())
                                  .center_channel;

        request->center_frequency() = son::wireless_utils::channel_to_freq(center_channel);

        LOG(DEBUG) << "Sending ZWDFS_ANT_CHANNEL_SWITCH_REQUEST on, channel="
                   << m_selected_channel.channel
                   << ", bw=" << utils::convert_bandwidth_to_int(m_selected_channel.bw);

        message_com::send_cmdu(fronthaul_sd, m_cmdu_tx);

        constexpr uint8_t CAC_STARTED_TIMEOUT_SEC = 10;
        m_zwdfs_fsm_timeout =
            std::chrono::steady_clock::now() + std::chrono::seconds(CAC_STARTED_TIMEOUT_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED);
        break;
    }
    case eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for CAC-STARTED notification!";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
        }
        break;
    }
    case eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for CAC-COMPLETED notification!";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
        }
        auto db = AgentDB::get();

        auto cac_remaining_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                     m_zwdfs_fsm_timeout - std::chrono::steady_clock::now())
                                     .count();
        db->statuses.zwdfs_cac_remaining_time_sec = cac_remaining_sec;

        break;
    }
    case eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO: {
        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        request->cs_params().channel   = m_selected_channel.channel;
        request->cs_params().bandwidth = m_selected_channel.bw;

        // At this point the selected channel is validated to be the the channels table, so
        // using '.at()' is safe.
        auto center_channel = son::wireless_utils::channels_table_5g.at(m_selected_channel.channel)
                                  .at(m_selected_channel.bw)
                                  .center_channel;

        request->cs_params().vht_center_frequency =
            son::wireless_utils::channel_to_freq(center_channel);

        auto fronthaul_sd = front_iface_name_to_socket(m_zwdfs_primary_radio_iface);
        if (!fronthaul_sd) {
            LOG(DEBUG) << "socket to fronthaul not found: " << m_zwdfs_primary_radio_iface;
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
            break;
        }

        message_com::send_cmdu(fronthaul_sd, m_cmdu_tx);

        constexpr uint8_t SWITCH_CHANNEL_PRIMARY_RADIO_TIMEOUT_SEC = 1;
        m_zwdfs_fsm_timeout = std::chrono::steady_clock::now() +
                              std::chrono::seconds(SWITCH_CHANNEL_PRIMARY_RADIO_TIMEOUT_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION);
        break;
    }
    case eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for PRIMARY_RADIO_CSA notification!";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
        }
        break;
    }
    case eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST: {
        // Block switching back 2.4G antenna if its radio is during background scan.
        auto db = AgentDB::get();
        auto break_state = false;
        for (const auto &radio : db->get_radios_list()) {
            if (!radio) {
                continue;
            }
            if (radio->freq_type == eFreqType::FREQ_24G &&
                radio->statuses.dcs_background_scan_in_process) {
                break_state = true;
                break;
            }
        }
        if (break_state) {
            break;
        }
        auto fronthaul_sd = front_iface_name_to_socket(m_zwdfs_iface);
        if (!fronthaul_sd) {
            LOG(DEBUG) << "socket to fronthaul not found: " << m_zwdfs_iface;
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
            break;
        }

        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        request->ant_switch_on() = false;

        message_com::send_cmdu(fronthaul_sd, m_cmdu_tx);

        constexpr uint8_t ZWDFS_SWITCH_ANT_OFF_RESPONSE_SEC = 1;

        m_zwdfs_fsm_timeout = std::chrono::steady_clock::now() +
                              std::chrono::seconds(ZWDFS_SWITCH_ANT_OFF_RESPONSE_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE);
        break;
    }
    case eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for ZWDFS_SWITCH_ANT_OFF notification!";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
        }
        break;
    }
    default:
        break;
    }
}

ChannelSelectionTask::sSelectedChannel
ChannelSelectionTask::zwdfs_select_best_usable_channel(const std::string &front_radio_iface)
{
    auto db = AgentDB::get();

    sSelectedChannel channel_selection = {};

    auto radio = db->radio(front_radio_iface);
    if (!radio) {
        return sSelectedChannel();
    }

    int32_t best_rank = INT32_MAX;

    // Initialize the best channel to the current channel, and add the ranking threshold
    // so only channel that has a better rank than the current channel (with threshold),
    // could be selected.
    int32_t current_rank_with_threshold;
    for (const auto &channel_bw_info : radio->channels_list.at(radio->channel).supported_bw_list) {
        if (channel_bw_info.bandwidth == radio->bandwidth) {
            current_rank_with_threshold =
                channel_bw_info.rank - db->device_conf.best_channel_rank_threshold;
            best_rank                   = current_rank_with_threshold;
            channel_selection.channel   = radio->channel;
            channel_selection.bw        = channel_bw_info.bandwidth;
            channel_selection.dfs_state = radio->channels_list.at(radio->channel).dfs_state;
            if (current_rank_with_threshold < 0) {
                current_rank_with_threshold = 0;
            }
            break;
        }
    }

    for (const auto &channel_info_pair : radio->channels_list) {
        uint8_t channel = channel_info_pair.first;
        auto dfs_state  = channel_info_pair.second.dfs_state;
        if (dfs_state == beerocks_message::eDfsState::UNAVAILABLE) {
            continue;
        }
        for (const auto &supported_bw : channel_info_pair.second.supported_bw_list) {

            if (supported_bw.rank == -1) {
                continue;
            }
            // Low rank is better.
            if (supported_bw.rank > best_rank) {
                continue;
            }
            if (supported_bw.rank == best_rank && supported_bw.bandwidth < channel_selection.bw) {
                continue;
            }

            bool update_best_channel = false;

            auto filter_channel_bw_with_unavailable_overlapping_channel = [&]() {
                auto channel_it = son::wireless_utils::channels_table_5g.find(channel);
                if (channel_it == son::wireless_utils::channels_table_5g.end()) {
                    LOG(ERROR) << "Radio supports channel which is not on the channel table! ch="
                               << int(channel);
                    return false;
                }

                auto &channel_bw_info_map = channel_it->second;
                auto bw_it                = channel_bw_info_map.find(supported_bw.bandwidth);
                if (bw_it == channel_bw_info_map.end()) {
                    LOG(ERROR) << "Radio supports channel which is not on the channel table!"
                               << "ch =" << int(channel) << ", bw="
                               << utils::convert_bandwidth_to_int(supported_bw.bandwidth);
                    return false;
                }

                auto channel_range_min = bw_it->second.overlap_beacon_channels_range.first;
                auto channel_range_max = bw_it->second.overlap_beacon_channels_range.second;

                constexpr uint8_t channels_distance_5g = 4;

                // Ignore if one of beacon channels is unavailable.
                for (uint8_t overlap_ch = channel_range_min; overlap_ch <= channel_range_max;
                     overlap_ch += channels_distance_5g) {

                    auto overlap_channel_info_it = radio->channels_list.find(overlap_ch);
                    if (overlap_channel_info_it == radio->channels_list.end()) {
                        LOG(ERROR)
                            << "Channel " << channel << " supprots bw="
                            << utils::convert_bandwidth_to_int(supported_bw.bandwidth)
                            << " but beacon channel=" << int(overlap_ch) << " is not supported!";

                        return false;
                    }

                    auto overlapping_channel_dfs_state = overlap_channel_info_it->second.dfs_state;
                    if (overlapping_channel_dfs_state == beerocks_message::eDfsState::UNAVAILABLE) {
                        return true;
                    }

                    // If get here the switch to the channel is possible. Need to update the dfs
                    // to the worst according to that order:
                    static const std::map<beerocks_message::eDfsState, uint8_t> dfs_state_order = {
                        {beerocks_message::eDfsState::NOT_DFS, 0},
                        {beerocks_message::eDfsState::AVAILABLE, 1},
                        {beerocks_message::eDfsState::USABLE, 2},
                    };

                    if (dfs_state_order.at(overlapping_channel_dfs_state) >
                        dfs_state_order.at(dfs_state)) {
                        dfs_state = overlapping_channel_dfs_state;
                    }
                }
                update_best_channel = true;
                return true;
            };

            switch (supported_bw.bandwidth) {
            case beerocks::BANDWIDTH_20: {
                update_best_channel = true;
                break;
            }
            case beerocks::BANDWIDTH_40:
            case beerocks::BANDWIDTH_80:
            case beerocks::BANDWIDTH_160: {
                // The function updates 'update_best_channel' value.
                if (!filter_channel_bw_with_unavailable_overlapping_channel()) {
                    return sSelectedChannel();
                }
                break;
            }
            default:
                break;
            }

            if (!update_best_channel) {
                continue;
            }

            best_rank                   = supported_bw.rank;
            channel_selection.channel   = channel;
            channel_selection.bw        = supported_bw.bandwidth;
            channel_selection.dfs_state = dfs_state;
        }
    }

    return channel_selection;
}

bool ChannelSelectionTask::initialize_zwdfs_interface_name()
{
    if (!m_zwdfs_iface.empty()) {
        return true;
    }

    auto db = AgentDB::get();

    const auto &configured_radios_list = db->device_conf.front_radio.config;

    for (const auto &radio_conf_pair : configured_radios_list) {
        auto &radio_iface_name = radio_conf_pair.first;

        auto radio = db->radio(radio_iface_name);
        if (!radio) {
            continue;
        }

        if (radio->front.zwdfs) {
            m_zwdfs_iface = radio->front.iface_name;
            return true;
        }
    }
    return false;
}

} // namespace beerocks
