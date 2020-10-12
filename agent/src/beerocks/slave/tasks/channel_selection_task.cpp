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
    for (const auto &radio : db->get_radios_list()) {
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
            handle_vs_channels_list_notification(cmdu_rx, sd, beerocks_header);
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
    LOG(TRACE) << "received cACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION";

    // TODO
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
    LOG(TRACE) << "received sACTION_APMANAGER_HOSTAP_DFS_CSA_ERROR_NOTIFICATION";

    // TODO
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
    LOG(TRACE) << "received sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION";

    // TODO
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
    LOG(TRACE) << "received sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION";

    // TODO
}

void ChannelSelectionTask::handle_vs_channels_list_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
    std::shared_ptr<beerocks_header> beerocks_header)
{
    LOG(TRACE) << "received sACTION_APMANAGER_CHANNELS_LIST_RESPONSE";

    // TODO
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
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE";

    // TODO

const std::string ChannelSelectionTask::socket_to_front_iface_name(const Socket *sd)
{
    for (const auto &soc : m_btl_ctx.slaves_sockets) {
        if (soc->slave == sd) {
            return soc->hostap_iface;
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
    return nullptr;
}

void ChannelSelectionTask::zwdfs_fsm()
{
    bool fsm_continue = false;
    do {
        switch (m_zwdfs_state) {
        case eZwdfsState::NOT_RUNNING: {
            break;
        }
        case eZwdfsState::REQUEST_CHANNELS_LIST: {
            break;
        }
        case eZwdfsState::WAIT_FOR_CHANNELS_LIST: {
            break;
        }
        case eZwdfsState::CHOOSE_NEXT_BEST_CHANNEL: {
            break;
        }
        case eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST: {
            break;
        }
        case eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED: {
            break;
        }
        case eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED: {
            break;
        }
        case eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO: {
            break;
        }
        case eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION: {
            break;
        }
        case eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST: {
            break;
        }
        case eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE: {
            break;
        }
        default:
            break;
        }
    } while (fsm_continue);
}

bool ChannelSelectionTask::initialize_zwdfs_interface_name()
{
    if (!m_zwdfs_iface.empty()) {
        return true;
    }

    auto db = AgentDB::get();

    auto &configured_radios_list = db->device_conf.front_radio.config;

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
