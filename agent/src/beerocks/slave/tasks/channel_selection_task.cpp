/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "channel_selection_task.h"
#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager.h"
#include "../cac_status_database.h"

#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <beerocks/tlvf/beerocks_message_backhaul.h>
#include <tlvf/wfa_map/tlvChannelPreference.h>
#include <tlvf/wfa_map/tlvOperatingChannelReport.h>
#include <tlvf/wfa_map/tlvProfile2CacCompletionReport.h>
#include <tlvf/wfa_map/tlvProfile2CacStatusReport.h>
#include <tlvf/wfa_map/tlvRadioOperationRestriction.h>
#include <tlvf/wfa_map/tlvTransmitPowerLimit.h>

#include "task_messages.h"
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

// Declaration for static class constants
constexpr int8_t ChannelSelectionTask::ZWDFS_FLOW_MAX_RETRIES;
constexpr int16_t ChannelSelectionTask::ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC;

/**
 * @brief Returns the preference score of a given channel.
 * 
 * @param[in] channel_preferences Reference to the preference map.
 * @param[in] operating_class Channel's operating class.
 * @param[in] channel_number Channel's number.
 * 
 * @return Cumulative preference score of the given channel.
 */
uint8_t
get_preference_for_channel(const AgentDB::sRadio::channel_preferences_map &channel_preferences,
                           uint8_t operating_class, uint8_t channel_number)
{

    // Check if Operating Class is present in preference
    if (std::find_if(
            channel_preferences.begin(), channel_preferences.end(),
            [operating_class](
                const AgentDB::sRadio::channel_preferences_map::const_reference &iter) {
                return (iter.first.operating_class == operating_class);
            }) == channel_preferences.end()) {
        // Preference does not support the Operating Class, returning Non-Operable
        return (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE;
    }

    // Check if channel present in operating class
    if (!son::wireless_utils::is_channel_in_operating_class(operating_class, channel_number)) {
        // Channel is not present in Operating Class, returning Non-Operable
        return (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE;
    }

    bool operating_class_is_present = false;

    for (const auto &preference_iter : channel_preferences) {
        // Check if correct operating class
        if (preference_iter.first.operating_class == operating_class) {
            operating_class_is_present = true;
            // Check if the preference's channel-list is empty.
            if (preference_iter.second.empty()) {
                // All channels in the operating class have the same preference.
                return preference_iter.first.flags.preference;
            }
            // Check if channel present in radio preference's channel-list.
            const auto channel_iter = preference_iter.second.find(channel_number);
            if (channel_iter == preference_iter.second.end()) {
                continue;
            }
            return preference_iter.first.flags.preference;
        }
    }

    if (!operating_class_is_present) {
        LOG(ERROR) << "Preference does not support Operating Class " << operating_class;
        return (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE;
    }

    /**
     * If this is reached it means that even though the preference
     * contains the operating class, it does not contain the specific
     * channel in it's channel list.
     * This means that we need to assume that the channel has the
     * highest preference.
     */
    LOG(DEBUG) << "Could not find Channel " << channel_number << " in the preference!";
    return (uint8_t)beerocks::eChannelPreferenceRankingConsts::BEST;
}

/**
 * @brief Returns the cumulative preference of a given channel.
 * 
 * @param[in] radio Pointer to the AgentDB's radio element.
 * @param[in] controller_preferences Reference to the controller's preference map.
 * @param[in] operating_class Channel's operating class.
 * @param[in] channel_number Channel's number.
 * 
 * @return Cumulative preference score of the given channel.
 */
uint8_t
get_cumulative_preference(const AgentDB::sRadio *radio,
                          const AgentDB::sRadio::channel_preferences_map &controller_preferences,
                          uint8_t operating_class, uint8_t channel_number)
{
    constexpr uint8_t NON_OPERABLE =
        (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE;
    if (operating_class == NON_OPERABLE) {
        // Skip invalid operating class
        return NON_OPERABLE;
    }

    // Get Controller's reported preference
    const auto controller_preference =
        get_preference_for_channel(controller_preferences, operating_class, channel_number);

    // Get Radio's reported preference
    const auto radio_preference =
        get_preference_for_channel(radio->channel_preferences, operating_class, channel_number);

    if (radio_preference == NON_OPERABLE || controller_preference == NON_OPERABLE) {
        return NON_OPERABLE;
    }

    const auto cumulative_preference = (radio_preference + controller_preference);

    LOG(INFO) << "Channel: " << channel_number << " "
              << "Operating Class: " << operating_class << " "
              << "Bandwidth: "
              << utils::convert_bandwidth_to_int(
                     son::wireless_utils::operating_class_to_bandwidth(operating_class))
              << "MHz "
              << "has a cumulative preference of " << cumulative_preference << "("
              << radio_preference << "+" << controller_preference << ")";
    return cumulative_preference;
}

ChannelSelectionTask::ChannelSelectionTask(BackhaulManager &btl_ctx,
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

void ChannelSelectionTask::handle_event(uint8_t event_enum_value, const void *event_obj)
{
    switch (eEvent(event_enum_value)) {
    case AP_DISABLED: {
        if (!event_obj) {
            LOG(ERROR) << "Received AP_DISABLED event without interface";
            break;
        }

        auto specific_iface_ptr = reinterpret_cast<const std::string *>(event_obj);

        handle_ap_disabled_event(*specific_iface_ptr);

        break;
    }
    case AP_ENABLED: {
        if (!event_obj) {
            LOG(ERROR) << "Received AP_ENABLED event without interface";
            break;
        }

        auto specific_iface_ptr = reinterpret_cast<const std::string *>(event_obj);

        handle_ap_enable_event(*specific_iface_ptr);

        break;
    }

    default: {
        LOG(DEBUG) << "Message handler doesn't exists for event type " << event_enum_value;
        break;
    }
    }
}

bool ChannelSelectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                                       const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                                       std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CHANNEL_PREFERENCE_QUERY_MESSAGE: {
        handle_channel_preference_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_REQUEST_MESSAGE: {
        handle_channel_selection_request(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::VENDOR_SPECIFIC_MESSAGE: {
        // Internally, the 'handle_vendor_specific' might not really handle
        // the CMDU, thus we need to return the real return value and not 'true'.
        return handle_vendor_specific(cmdu_rx, src_mac, fd, beerocks_header);
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void ChannelSelectionTask::handle_channel_preference_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                           const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    LOG(DEBUG) << "Received CHANNEL_PREFERENCE_QUERY_MESSAGE from " << src_mac
               << " with mid=" << std::hex << mid;

    // Clear previous request, if any
    m_pending_preference.preference_ready.clear();
    m_pending_preference.mid = mid;

    LOG(DEBUG) << "Received CHANNEL_PREFERENCE_QUERY_MESSAGE, mid=" << std::dec << int(mid);

    auto db = AgentDB::get();

    for (const auto radio : db->get_radios_list()) {
        LOG(DEBUG) << "Sending ACTION_BACKHAUL_CHANNELS_LIST_REQUEST to radio "
                   << radio->front.iface_mac;

        m_pending_preference.preference_ready[radio->front.iface_mac] = false;

        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_REQUEST>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        auto agent_fd = m_btl_ctx.get_agent_fd();
        if (agent_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(ERROR) << "socket to Agent not found";
            break;
        }

        auto action_header         = message_com::get_beerocks_header(m_cmdu_tx)->actionhdr();
        action_header->radio_mac() = radio->front.iface_mac;

        m_btl_ctx.send_cmdu(agent_fd, m_cmdu_tx);
    }
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
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, db->controller_info.bridge_mac, db->bridge.mac);
}

bool ChannelSelectionTask::handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac, int sd,
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
    if (beerocks_header->action() != beerocks_message::ACTION_BACKHAUL) {
        return false;
    }

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
    return true;
}

void ChannelSelectionTask::handle_vs_csa_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, int fd, std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CSA_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION failed";
        return;
    }

    auto db = AgentDB::get();
    auto radio =
        db->get_radio_by_mac(beerocks_header->actionhdr()->radio_mac(), AgentDB::eMacType::RADIO);
    if (!radio) {
        return;
    }

    const auto &sender_iface_name = radio->front.iface_name;

    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION from " << sender_iface_name;

    // send inner task message
    auto switch_channel_notification = std::make_shared<sSwitchChannelNotification>();
    if (!switch_channel_notification) {
        LOG(ERROR) << "unable to create switch-channel-notification message";
        return;
    }

    switch_channel_notification->ifname            = sender_iface_name;
    switch_channel_notification->ap_channel_switch = notification->cs_params();
    switch_channel_notification->switched          = true;
    m_btl_ctx.m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_NOTIFICATION_EVENT,
                                     switch_channel_notification);

    auto sender_radio = db->radio(sender_iface_name);
    if (!sender_radio) {
        return;
    }

    auto sub_band_dfs_enable = db->device_conf.front_radio.config[sender_iface_name].sub_band_dfs;

    if (db->device_conf.zwdfs_enable) {
        // Initiate Agent Managed ZWDFS flow.
        if (notification->cs_params().switch_reason == beerocks::CH_SWITCH_REASON_RADAR) {
            if (!sub_band_dfs_enable && !sender_radio->front.zwdfs &&
                m_zwdfs_state != eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED &&
                m_zwdfs_state != eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED) {

                m_zwdfs_primary_radio_iface = sender_radio->front.iface_name;
                // Start ZWDFS flow
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::INIT_ZWDFS_FLOW);
                return;
            }
        } else if (zwdfs_in_process()) {
            // Channel switch reason != RADAR
            if (sender_iface_name == m_zwdfs_primary_radio_iface) {

                auto external_channel_switch =
                    (m_zwdfs_state != eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION);

                if (external_channel_switch) {
                    abort_zwdfs_flow(true);
                    return;
                } else {
                    // When clearing the next-best-channel - if CAC fails we try again on the next-next-best-channel.
                    // The general case expects the next channel to also be a DFS channel so we do not release the antenna just yet.
                    // In case the next-next-best-channel will be non-DFS, we need to make sure to release the antenna when flow completes.
                    if (m_zwdfs_ant_in_use) {
                        LOG(DEBUG) << "Release ZWDFS antenna in use";
                        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
                    } else {
                        ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
                    }
                    return;
                }
            }
        }
    }
}

void ChannelSelectionTask::handle_vs_csa_error_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, int fd, std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header
            ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CSA_ERROR_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION failed";
        return;
    }

    auto db = AgentDB::get();
    auto radio =
        db->get_radio_by_mac(beerocks_header->actionhdr()->radio_mac(), AgentDB::eMacType::RADIO);
    if (!radio) {
        return;
    }

    const auto &sender_iface_name = radio->front.iface_name;

    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CSA_ERROR_NOTIFICATION from "
               << sender_iface_name;

    // send inner task message
    auto switch_channel_notification = std::make_shared<sSwitchChannelNotification>();
    if (!switch_channel_notification) {
        LOG(ERROR) << "unable to create switch-channel-notification message";
        return;
    }

    switch_channel_notification->ifname            = sender_iface_name;
    switch_channel_notification->ap_channel_switch = notification->cs_params();
    switch_channel_notification->switched          = false;
    m_btl_ctx.m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_NOTIFICATION_EVENT,
                                     switch_channel_notification);

    std::string which_radio;
    if (zwdfs_in_process()) {
        if (sender_iface_name == m_zwdfs_iface) {
            which_radio = "ZWDFS";
        } else if (sender_iface_name == m_zwdfs_primary_radio_iface) {
            which_radio = "Primary 5G";
        }
        LOG(DEBUG) << "Failed to switch channel on " << which_radio << " radio, "
                   << sender_iface_name << ". Reset ZWDFS flow !";

        if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
            LOG(WARNING) << "Too many retries to switch channel (" << int(ZWDFS_FLOW_MAX_RETRIES)
                         << "), aborting.";
            m_next_retry_time = std::chrono::steady_clock::now();
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            return;
        }

        // Retry restarting the ZWDFS flow
        ++m_retry_counter;
        LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/" << int(ZWDFS_FLOW_MAX_RETRIES)
                   << ")";
        m_next_retry_time = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
        return;
    }
}

void ChannelSelectionTask::abort_zwdfs_flow(bool external_channel_switch)
{
    if (!zwdfs_in_process()) {
        return;
    }

    if (external_channel_switch) {
        LOG(DEBUG) << "External channel switch detected - Abort ZWDFS in progress:"
                   << " state=" << m_zwdfs_states_string.at(m_zwdfs_state);
    }

    if (m_zwdfs_ant_in_use) {
        LOG(DEBUG) << "Release ZWDFS antenna in use";
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
    } else {
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
    }
}

void ChannelSelectionTask::handle_vs_cac_started_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, int fd, std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header
            ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_DFS_CAC_STARTED_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION failed";
        return;
    }

    auto db = AgentDB::get();
    auto radio =
        db->get_radio_by_mac(beerocks_header->actionhdr()->radio_mac(), AgentDB::eMacType::RADIO);
    if (!radio) {
        return;
    }

    const auto &sender_iface_name = radio->front.iface_name;

    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION from "
               << sender_iface_name;

    // send inner task message
    auto cac_started_notification = std::make_shared<sCacStartedNotification>();
    if (!cac_started_notification) {
        LOG(ERROR) << "unable to create cac-started-notification message";
        return;
    }
    cac_started_notification->ifname             = sender_iface_name;
    cac_started_notification->cac_started_params = notification->params();
    m_btl_ctx.m_task_pool.send_event(eTaskEvent::CAC_STARTED_NOTIFICATION,
                                     cac_started_notification);

    // CAC_STARTED event is received when moving to DFS usable channel.
    // If this event is received unexpectedly (because of external channel switch),
    // we should abort the current ZW-DFS flow.
    if (sender_iface_name == m_zwdfs_primary_radio_iface) {
        abort_zwdfs_flow();
        return;
    }

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED) {
        // Set timeout for CAC-COMPLETED notification with the CAC duration received on this
        // this notification, multiplied in factor of 1.2.
        constexpr float CAC_DURATION_FACTOR = 1.2;
        auto cac_remaining_sec =
            uint16_t(notification->params().cac_duration_sec * CAC_DURATION_FACTOR);
        db->statuses.zwdfs_cac_remaining_time_sec = cac_remaining_sec;
        m_zwdfs_fsm_timeout =
            std::chrono::steady_clock::now() + std::chrono::seconds(cac_remaining_sec);
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED);
    } else {
        LOG(WARNING) << "Received unexpected cACTION_BACKHAUL_HOSTAP_DFS_CAC_STARTED_NOTIFICATION:"
                     << " state=" << m_zwdfs_states_string.at(m_zwdfs_state);
    }
}

void ChannelSelectionTask::handle_vs_dfs_cac_completed_notification(
    ieee1905_1::CmduMessageRx &cmdu_rx, int fd, std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification =
        beerocks_header
            ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION>();
    if (!notification) {
        LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION failed";
        return;
    }

    auto db = AgentDB::get();
    auto radio =
        db->get_radio_by_mac(beerocks_header->actionhdr()->radio_mac(), AgentDB::eMacType::RADIO);
    if (!radio) {
        return;
    }

    const auto &sender_iface_name = radio->front.iface_name;

    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION from "
               << sender_iface_name << ", status=" << notification->params().success;

    // send inner task message
    auto cac_completed_notification = std::make_shared<sCacCompletedNotification>();
    if (!cac_completed_notification) {
        LOG(ERROR) << "unable to create cac-completed-notification message";
        return;
    }
    cac_completed_notification->ifname               = sender_iface_name;
    cac_completed_notification->cac_completed_params = notification->params();

    m_btl_ctx.m_task_pool.send_event(eTaskEvent::CAC_COMPLETED_NOTIFICATION,
                                     cac_completed_notification);

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED) {
        db->statuses.zwdfs_cac_remaining_time_sec = 0;
        if (notification->params().success != 1) {
            LOG(ERROR) << "CAC has failed! Trying next-best-channel";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
            return;
        }
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO);
    }
}

void ChannelSelectionTask::handle_vs_channels_list_response(
    ieee1905_1::CmduMessageRx &cmdu_rx, int fd, std::shared_ptr<beerocks_header> beerocks_header)
{
    const auto &radio_mac = beerocks_header->actionhdr()->radio_mac();
    auto db               = AgentDB::get();
    auto radio            = db->get_radio_by_mac(radio_mac, AgentDB::eMacType::RADIO);
    if (!radio) {
        return;
    }
    const auto &sender_iface_name = radio->front.iface_name;
    LOG(TRACE) << "received ACTION_APMANAGER_CHANNELS_LIST_RESPONSE from " << sender_iface_name;

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_CHANNELS_LIST) {
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::CHOOSE_NEXT_BEST_CHANNEL);
    } else if (m_pending_preference.mid > 0) {

        // If there is a pending preference query, need to build a preference report
        build_channel_preference_report(radio_mac);

        // Once the preference report is done (All radios have responded)
        if (channel_preference_report_ready()) {

            // Need to send the preference report back to the controller
            if (!send_channel_preference_report(cmdu_rx, beerocks_header)) {
                LOG(ERROR) << "Failed to send the CHANNEL_PREFERENCE_REPORT_MESSAGE!";
            }

            // Clear the pending preference MID.
            m_pending_preference.mid = 0;
        }
    }
}

void ChannelSelectionTask::handle_vs_zwdfs_ant_channel_switch_response(
    ieee1905_1::CmduMessageRx &cmdu_rx, int fd, std::shared_ptr<beerocks_header> beerocks_header)
{
    auto notification = beerocks_header->addClass<
        beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE>();
    if (!notification) {
        LOG(ERROR) << "addClass ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE failed";
        return;
    }

    auto db = AgentDB::get();
    auto radio =
        db->get_radio_by_mac(beerocks_header->actionhdr()->radio_mac(), AgentDB::eMacType::RADIO);
    if (!radio) {
        return;
    }
    const auto &sender_iface_name = radio->front.iface_name;
    LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE from "
               << sender_iface_name;

    if (m_zwdfs_state == eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE) {
        if (notification->success()) {
            m_zwdfs_ant_in_use = false;
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            return;
        }

        LOG(ERROR) << "Failed to switch ZWDFS antenna off";

        if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
            LOG(WARNING) << "Release the antenna max retries(" << ZWDFS_FLOW_MAX_RETRIES
                         << ") is reached, aborting.";
            m_next_retry_time = std::chrono::steady_clock::now();
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            return;
        }

        // increase retry counter
        ++m_retry_counter;
        LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/" << int(ZWDFS_FLOW_MAX_RETRIES)
                   << ")";
        LOG(DEBUG) << "Retry release the antenna within " << ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC
                   << " milliseconds";
        m_next_retry_time = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
        // Retry to switch antenna off
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
        return;
    }

    // Get here after switching on the ZWDFS antenna.
    if (!notification->success()) {
        LOG(ERROR) << "Failed to switch ZWDFS antenna on and into channel";
        m_zwdfs_ant_in_use = true;

        if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
            LOG(ERROR) << "Too many retries switching ZWDFS antenna on and into channel ("
                       << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
            m_next_retry_time = std::chrono::steady_clock::now();
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
            return;
        }

        // Retry ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST
        ++m_retry_counter;
        LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/" << int(ZWDFS_FLOW_MAX_RETRIES)
                   << ")";
        m_next_retry_time = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST);
        return;
    }
}

void ChannelSelectionTask::handle_ap_disabled_event(const std::string &iface)
{
    LOG(TRACE) << "Received AP_DISABLED event for iface=" << iface;

    if ((iface != m_zwdfs_primary_radio_iface) && (iface != m_zwdfs_iface)) {
        return;
    }

    if (iface == m_zwdfs_iface) {
        LOG(DEBUG) << "Received AP_DISABLED event for the ZW-DFS interface";
        m_zwdfs_ap_enabled = false;
    }

    abort_zwdfs_flow();
}

void ChannelSelectionTask::handle_ap_enable_event(const std::string &iface)
{
    LOG(TRACE) << "Received AP_ENABLED event for iface=" << iface;

    if (!initialize_zwdfs_interface_name()) {
        LOG(WARNING) << "No ZWDFS radio interface has been found. "
                        "AP_ENABLED before ZWDFS has been initiated.";
        return;
    }

    if (iface == m_zwdfs_iface) {
        LOG(DEBUG) << "Received AP_ENABLED event for the ZW-DFS interface";
        m_zwdfs_ap_enabled = true;

        LOG_IF((m_zwdfs_state == ZWDFS_SWITCH_ANT_OFF_REQUEST), DEBUG)
            << "Resume ZW-DFS antenna release";
    }
}

bool ChannelSelectionTask::build_channel_preference_report(const sMacAddr &radio_mac)
{
    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(radio_mac, AgentDB::eMacType::RADIO);
    if (!radio) {
        return false;
    }

    auto get_preference_key =
        [&radio](
            const uint8_t channel, const uint8_t operating_class,
            beerocks::eWiFiBandwidth operating_bandwidth) -> const AgentDB::sChannelPreference {
        // Channel is not supported.
        auto it_ch = radio->channels_list.find(channel);
        if (it_ch == radio->channels_list.end()) {
            return AgentDB::sChannelPreference(
                operating_class, wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
        }

        // Bandwidth of a channel is not supported.
        auto &supported_channel_info = it_ch->second;
        auto &supported_bw_list      = supported_channel_info.supported_bw_list;
        auto it_bw = std::find_if(supported_bw_list.begin(), supported_bw_list.end(),
                                  [&](const beerocks_message::sSupportedBandwidth &bw_info) {
                                      return bw_info.bandwidth == operating_bandwidth;
                                  });
        if (it_bw == supported_bw_list.end()) {
            return AgentDB::sChannelPreference(
                operating_class, wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
        }

        if (supported_channel_info.dfs_state == beerocks_message::eDfsState::UNAVAILABLE) {
            return AgentDB::sChannelPreference(
                operating_class, wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                wfa_map::cPreferenceOperatingClasses::eReasonCode::
                    OPERATION_DISALLOWED_DUE_TO_RADAR_DETECTION_ON_A_DFS_CHANNEL);
        }

        // Channel is supported and has a valid preference.
        return AgentDB::sChannelPreference(
            operating_class,
            static_cast<wfa_map::cPreferenceOperatingClasses::ePreference>(
                it_bw->multiap_preference),
            wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
    };

    // Received new preferences, clear old preferences
    radio->channel_preferences.clear();

    for (const auto &oper_class : son::wireless_utils::operating_classes_list) {
        const auto oper_class_num       = oper_class.first;
        const auto &oper_class_channels = oper_class.second.channels;
        const auto oper_class_bw        = oper_class.second.band;

        if (radio->freq_type != son::wireless_utils::which_freq_op_cls(oper_class_num)) {
            // Operating Class not part of the current radio, skip.
            continue;
        }

        for (auto channel_of_oper_class : oper_class_channels) {
            // Operating classes 128,129,130 use center channel **unlike the other classes**,
            // so convert center channel and bandwidth to main channel.
            // For more info, refer to Table E-4 in the 802.11 specification.
            const auto beacon_channels =
                son::wireless_utils::is_operating_class_using_central_channel(oper_class_num)
                    ? son::wireless_utils::center_channel_5g_to_beacon_channels(
                          channel_of_oper_class, oper_class_bw)
                    : std::vector<uint8_t>{channel_of_oper_class};

            // Assume non-operable
            AgentDB::sChannelPreference preference_key(
                oper_class_num, wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
            for (const auto beacon_channel : beacon_channels) {
                auto tmp_preference_key =
                    get_preference_key(beacon_channel, oper_class_num, oper_class_bw);
                if (tmp_preference_key.flags.preference == 0) {
                    LOG(INFO) << "Channel #" << beacon_channel << " in Class #" << oper_class_num
                              << " is non-operable";
                    if (preference_key.flags.reason_code < tmp_preference_key.flags.reason_code) {
                        preference_key.flags.reason_code = tmp_preference_key.flags.reason_code;
                    }
                } else if (preference_key.flags.preference < tmp_preference_key.flags.preference) {
                    // Set as the highest preference in the beacon channels
                    preference_key = tmp_preference_key;
                }
            }
            radio->channel_preferences[preference_key].insert(channel_of_oper_class);
        }
    }

    m_pending_preference.preference_ready[radio_mac] = true;
    return true;
}

bool ChannelSelectionTask::channel_preference_report_ready()
{
    if (m_pending_preference.preference_ready.empty()) {
        return false;
    }
    for (const auto &preference_ready : m_pending_preference.preference_ready) {
        if (!preference_ready.second) {
            // Channel preference report is not ready yet.
            return false;
        }
    }
    // Channel preference report is ready on all radios.
    return true;
}

bool ChannelSelectionTask::send_channel_preference_report(
    ieee1905_1::CmduMessageRx &cmdu_rx, std::shared_ptr<beerocks_header> beerocks_header)
{

    LOG(INFO) << "Building CHANNEL_PREFERENCE_REPORT_MESSAGE";
    // build channel preference report with the same MID as the query
    auto cmdu_tx_header = m_cmdu_tx.create(
        m_pending_preference.mid, ieee1905_1::eMessageType::CHANNEL_PREFERENCE_REPORT_MESSAGE);

    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type CHANNEL_PREFERENCE_REPORT_MESSAGE, has failed";
        return false;
    }

    auto db = AgentDB::get();

    for (const auto &pending_preference_iter : m_pending_preference.preference_ready) {
        if (!create_channel_preference_tlv(pending_preference_iter.first)) {
            LOG(ERROR) << "Failed to create Channel Preference TLV";
            return false;
        }
    }

    //create_radio_operation_restriction_tlv();

    // Need to send CAC TLVs only if Profile2 is supported //
    if (db->controller_info.profile_support >
        wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::MULTIAP_PROFILE_1) {

        create_cac_completion_report_tlv();
        create_cac_status_report_tlv();
    }

    if (db->controller_info.bridge_mac == beerocks::net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Controller MAC unknown.";
        return false;
    }

    LOG(DEBUG) << "sending channel preference report to broker";
    return m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, db->controller_info.bridge_mac, db->bridge.mac);
}

bool ChannelSelectionTask::create_channel_preference_tlv(const sMacAddr &radio_mac)
{
    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(radio_mac, AgentDB::eMacType::RADIO);
    if (!radio) {
        return false;
    }

    std::stringstream ss;

    auto channel_preference_tlv = m_cmdu_tx.addClass<wfa_map::tlvChannelPreference>();
    if (!channel_preference_tlv) {
        LOG(ERROR) << "addClass ieee1905_1::tlvChannelPreference has failed";
        return false;
    }

    channel_preference_tlv->radio_uid() = radio_mac;

    ss << "Preference for radio: " << channel_preference_tlv->radio_uid() << std::endl;

    for (const auto &preference : radio->channel_preferences) {
        auto &operating_class_info          = preference.first;
        auto &operating_class_channels_list = preference.second;

        auto op_class_channels = channel_preference_tlv->create_operating_classes_list();
        if (!op_class_channels) {
            LOG(ERROR) << "create_operating_classes_list() has failed!";
            return false;
        }

        op_class_channels->operating_class() = operating_class_info.operating_class;
        ss << "operating class #" << int(op_class_channels->operating_class());
        ss << " preference: " << int(operating_class_info.flags.preference);
        ss << " reason code: " << int(operating_class_info.flags.reason_code) << std::endl;

        if (!op_class_channels->alloc_channel_list(operating_class_channels_list.size())) {
            LOG(ERROR) << "alloc_channel_list() has failed!";
            return false;
        }

        ss << " channels: [";
        uint8_t idx = 0;
        for (auto channel : operating_class_channels_list) {
            ss << int(channel) << " ";
            *op_class_channels->channel_list(idx) = channel;
            idx++;
        }
        ss << "]." << std::endl;

        // Update channel list flags
        op_class_channels->flags() = operating_class_info.flags;

        // Push operating class object to the list of operating class objects
        if (!channel_preference_tlv->add_operating_classes_list(op_class_channels)) {
            LOG(ERROR) << "add_operating_classes_list() has failed!";
            return false;
        }
    }
    ss << std::endl;
    LOG(DEBUG) << ss.str();
    return true;
}

bool ChannelSelectionTask::create_radio_operation_restriction_tlv(const sMacAddr &radio_mac)
{
    // This is a stub for PPM-2042
    // Need to fill the Radio Operation Restrictions TLV
    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    return true;
}

bool ChannelSelectionTask::create_cac_completion_report_tlv()
{
    // create completion report
    auto cac_completion_report_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2CacCompletionReport>();
    if (!cac_completion_report_tlv) {
        LOG(ERROR) << "Failed to create cac-completion-report-tlv";
        return false;
    }

    CacStatusDatabase cac_status_database;
    auto db = AgentDB::get();

    for (const auto &pending_preference_iter : m_pending_preference.preference_ready) {
        const auto &radio_mac = pending_preference_iter.first;
        auto radio            = db->get_radio_by_mac(radio_mac);
        if (!radio) {
            LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
            return false;
        }

        auto cac_radio = cac_completion_report_tlv->create_cac_radios();
        if (!cac_radio) {
            LOG(ERROR) << "Failed to create cac radio for " << radio->front.iface_mac;
            return false;
        }

        cac_radio->radio_uid() = radio->front.iface_mac;
        const auto &cac_completion =
            cac_status_database.get_completion_status(radio->front.iface_mac);
        cac_radio->operating_class()       = cac_completion.first.operating_class;
        cac_radio->channel()               = cac_completion.first.channel;
        cac_radio->cac_completion_status() = cac_completion.first.completion_status;

        if (!cac_completion.second.empty()) {
            cac_radio->alloc_detected_pairs(cac_completion.second.size());
            for (unsigned int i = 0; i < cac_completion.second.size(); ++i) {
                if (std::get<0>(cac_radio->detected_pairs(i))) {
                    auto &cac_detected_pair = std::get<1>(cac_radio->detected_pairs(i));
                    cac_detected_pair.operating_class_detected = cac_completion.second[i].first;
                    cac_detected_pair.channel_detected         = cac_completion.second[i].second;
                }
            }
        }
        cac_completion_report_tlv->add_cac_radios(cac_radio);
    }

    return true;
}

bool ChannelSelectionTask::create_cac_status_report_tlv()
{

    CacStatusDatabase cac_status_database;
    auto db = AgentDB::get();
    CacAvailableChannels agent_avaliable_channels;

    for (const auto &pending_preference_iter : m_pending_preference.preference_ready) {
        const auto &radio_mac = pending_preference_iter.first;
        auto radio            = db->get_radio_by_mac(radio_mac);
        if (!radio) {
            LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
            return false;
        }
        // fill status report
        auto radio_available_channels =
            cac_status_database.get_available_channels(radio->front.iface_mac);
        agent_avaliable_channels.insert(agent_avaliable_channels.end(),
                                        radio_available_channels.begin(),
                                        radio_available_channels.end());
    }

    // create status report
    auto cac_status_report_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2CacStatusReport>();
    if (!cac_status_report_tlv) {
        LOG(ERROR) << "Failed to create cac-status-report-tlv";
        return false;
    }

    if (!cac_status_report_tlv->alloc_available_channels(agent_avaliable_channels.size())) {
        LOG(ERROR) << "Failed to allocate " << agent_avaliable_channels.size()
                   << " structures for available channels";
        return false;
    }

    for (unsigned int i = 0; i < agent_avaliable_channels.size(); ++i) {
        auto &available_ref           = std::get<1>(cac_status_report_tlv->available_channels(i));
        available_ref.operating_class = agent_avaliable_channels[i].operating_class;
        available_ref.channel         = agent_avaliable_channels[i].channel;
        available_ref.minutes_since_cac_completion =
            std::chrono::duration_cast<std::chrono::minutes>(agent_avaliable_channels[i].duration)
                .count();
    }

    return true;
}

bool ChannelSelectionTask::radio_scan_in_progress(eFreqType band)
{
    auto db = AgentDB::get();
    for (const auto radio : db->get_radios_list()) {
        if (!radio) {
            continue;
        }
        if (band != eFreqType::FREQ_UNKNOWN && radio->freq_type != band) {
            continue;
        }
        if (radio->statuses.channel_scan_in_progress) {
            return true;
        }
    }
    return false;
}

void ChannelSelectionTask::zwdfs_fsm()
{
    switch (m_zwdfs_state) {
    case eZwdfsState::NOT_RUNNING: {
        break;
    }
    case eZwdfsState::INIT_ZWDFS_FLOW: {
        m_retry_counter   = 0;
        m_next_retry_time = std::chrono::steady_clock::now();
        ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
        break;
    }
    case eZwdfsState::REQUEST_CHANNELS_LIST: {

        // Wait between retries if needed
        if (std::chrono::steady_clock::now() < m_next_retry_time) {
            break;
        }

        // Block the begining of the flow if background scan is running on one of the radios.
        // 2.4G because it is forbidden to switch zwdfs antenna during scan.
        // 5G because we don't want the ZWDFS flow will switch channel on the primary 5G radio
        // while it is during a background scan.
        if (radio_scan_in_progress()) {
            break;
        }

        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_REQUEST>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        auto agent_fd = m_btl_ctx.get_agent_fd();
        if (agent_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(DEBUG) << "socket to Agent not found";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        // Filling the radio mac. This is temporary the task will be moved to the agent (PPM-1680).
        auto db    = AgentDB::get();
        auto radio = db->radio(m_zwdfs_primary_radio_iface);
        if (!radio) {
            break;
        }
        auto action_header         = message_com::get_beerocks_header(m_cmdu_tx)->actionhdr();
        action_header->radio_mac() = radio->front.iface_mac;

        m_btl_ctx.send_cmdu(agent_fd, m_cmdu_tx);

        constexpr uint8_t CHANNELS_LIST_RESPONSE_TIMEOUT_SEC = 3;

        m_zwdfs_fsm_timeout = std::chrono::steady_clock::now() +
                              std::chrono::seconds(CHANNELS_LIST_RESPONSE_TIMEOUT_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_CHANNELS_LIST);
        break;
    }
    case eZwdfsState::WAIT_FOR_CHANNELS_LIST: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for channels list response";

            if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
                LOG(ERROR) << "Too many retries getting channels list response("
                           << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
                m_next_retry_time = std::chrono::steady_clock::now();
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
                break;
            }

            // Retry getting channels list response
            ++m_retry_counter;
            LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/"
                       << int(ZWDFS_FLOW_MAX_RETRIES) << ")";
            m_next_retry_time = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
            break;
        }
        break;
    }
    case eZwdfsState::CHOOSE_NEXT_BEST_CHANNEL: {
        m_selected_channel = select_best_usable_channel(m_zwdfs_primary_radio_iface);
        if (m_selected_channel.channel == 0) {
            LOG(ERROR) << "Error occurred on second best channel selection";
            if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
                LOG(ERROR) << "Too many retries when selecting best usable channel ("
                           << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
                m_next_retry_time = std::chrono::steady_clock::now();
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
                break;
            }

            // Retry REQUEST_CHANNELS_LIST
            ++m_retry_counter;
            LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/"
                       << int(ZWDFS_FLOW_MAX_RETRIES) << ")";
            m_next_retry_time = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::REQUEST_CHANNELS_LIST);
            break;
        }

        auto db = AgentDB::get();

        auto radio = db->radio(m_zwdfs_primary_radio_iface);
        if (!radio) {
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        // If there is a channel with better rank, but did not pass the ranking threshold, print
        // information about it.
        int32_t current_channel_rank = -1;
        for (const auto &channel_bw_info :
             radio->channels_list.at(radio->channel).supported_bw_list) {
            if (channel_bw_info.bandwidth == radio->bandwidth) {
                current_channel_rank = channel_bw_info.rank;
            }
        }

        // If current channel has invalid rank.
        if (current_channel_rank == -1) {
            LOG(DEBUG) << "Current channel rank not found! Ignoring rank_threshold_limit="
                       << db->device_conf.best_channel_rank_threshold
                       << " switching to the selected channel";
        } else if ((m_selected_channel.rank < current_channel_rank) &&
                   (uint32_t(current_channel_rank - m_selected_channel.rank) <
                    db->device_conf.best_channel_rank_threshold)) {
            // If current channel has valid rank and selected channel doesn't meet the threshold requirement,
            // no need to switch-channel
            LOG(INFO)
                << "Channel " << m_selected_channel.channel << " with bw=" << m_selected_channel.bw
                << " and dfs_state=" << m_selected_channel.dfs_state
                << " has better rank than current channel, but did not pass the ranking threshold="
                << db->device_conf.best_channel_rank_threshold << ", Current channel is selected.";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        // If current channel is the best channel - no need to switch-channel
        if (m_selected_channel.channel == radio->channel &&
            m_selected_channel.bw == radio->bandwidth) {
            LOG(DEBUG) << "Failsafe is already second best channel, abort ZWDFS flow";
            if (m_zwdfs_ant_in_use) {
                LOG(DEBUG) << "Release ZWDFS antenna in use";
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
            } else {
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            }
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
        // switch the channel immediately on the primary 5G radio.
        if (m_selected_channel.dfs_state == beerocks_message::eDfsState::NOT_DFS ||
            m_selected_channel.dfs_state == beerocks_message::eDfsState::AVAILABLE) {
            LOG(WARNING) << "Better failsafe channel has been found, skip ZWDFS CAC, and switch "
                            "primary 5G radio immediately";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO);
            break;
        }

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST);
        break;
    }
    case eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST: {

        // Wait between retries if needed
        if (std::chrono::steady_clock::now() < m_next_retry_time) {
            break;
        }

        // Stop ZWDFS flow from doing CAC if a background scan has started before we switch the
        // ZWDFS antenna. Since at the time when the background scan will be over, the selected
        // channel might not be relevant anymore, the FSM will start over and jum to the initial
        // state which query the updated channel info from the AP.
        if (!m_zwdfs_ap_enabled) {
            LOG(ERROR) << "ZW-DFS antenna interface is down. Unable to switch to DFS channel "
                          "using ZW-DFS. Aborting flow.";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        if (radio_scan_in_progress()) {
            LOG(INFO) << "Pause ZWDFS flow until background scan is finished";
            break;
        }

        auto agent_fd = m_btl_ctx.get_agent_fd();
        if (agent_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(DEBUG) << "socket to Agent not found";
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

        m_zwdfs_ant_in_use = true;
        m_btl_ctx.send_cmdu(agent_fd, m_cmdu_tx);

        constexpr uint8_t CAC_STARTED_TIMEOUT_SEC = 10;
        m_zwdfs_fsm_timeout =
            std::chrono::steady_clock::now() + std::chrono::seconds(CAC_STARTED_TIMEOUT_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED);
        break;
    }
    case eZwdfsState::WAIT_FOR_ZWDFS_CAC_STARTED: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for CAC-STARTED notification!";

            if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
                LOG(ERROR) << "Too many retries waiting for CAC-STARTED ("
                           << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
                m_next_retry_time = std::chrono::steady_clock::now();
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
                break;
            }

            // Retry ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST
            ++m_retry_counter;
            LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/"
                       << int(ZWDFS_FLOW_MAX_RETRIES) << ")";
            m_next_retry_time = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST);
            break;
        }
        break;
    }
    case eZwdfsState::WAIT_FOR_ZWDFS_CAC_COMPLETED: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for CAC-COMPLETED notification!";

            if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
                LOG(ERROR) << "Too many retries waiting for CAC_COMPLETED ("
                           << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
                m_next_retry_time = std::chrono::steady_clock::now();
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
                break;
            }

            // Retry ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST
            ++m_retry_counter;
            LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/"
                       << int(ZWDFS_FLOW_MAX_RETRIES) << ")";
            m_next_retry_time = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST);
            break;
        }
        auto db = AgentDB::get();

        auto cac_remaining_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                     m_zwdfs_fsm_timeout - std::chrono::steady_clock::now())
                                     .count();
        db->statuses.zwdfs_cac_remaining_time_sec = cac_remaining_sec;

        break;
    }
    case eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO: {

        // Wait between retries if needed
        if (std::chrono::steady_clock::now() < m_next_retry_time) {
            break;
        }

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

        auto agent_fd = m_btl_ctx.get_agent_fd();
        if (agent_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(DEBUG) << "socket to Agent not found";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
            break;
        }

        // Filling the radio mac. This is temporary the task will be moved to the agent (PPM-1680).
        auto db    = AgentDB::get();
        auto radio = db->radio(m_zwdfs_primary_radio_iface);
        if (!radio) {
            break;
        }
        auto action_header         = message_com::get_beerocks_header(m_cmdu_tx)->actionhdr();
        action_header->radio_mac() = radio->front.iface_mac;

        m_btl_ctx.send_cmdu(agent_fd, m_cmdu_tx);

        constexpr uint8_t SWITCH_CHANNEL_PRIMARY_RADIO_TIMEOUT_SEC = 3;
        m_zwdfs_fsm_timeout = std::chrono::steady_clock::now() +
                              std::chrono::seconds(SWITCH_CHANNEL_PRIMARY_RADIO_TIMEOUT_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION);
        break;
    }
    case eZwdfsState::WAIT_FOR_PRIMARY_RADIO_CSA_NOTIFICATION: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for PRIMARY_RADIO_CSA notification!";
            if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
                LOG(ERROR) << "Too many retries waiting for PRIMARY_RADIO_CSA_NOTIFICATION ("
                           << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
                m_next_retry_time = std::chrono::steady_clock::now();
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
                break;
            }

            // Retry SWITCH_CHANNEL_PRIMARY_RADIO
            ++m_retry_counter;
            LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/"
                       << int(ZWDFS_FLOW_MAX_RETRIES) << ")";
            m_next_retry_time = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::SWITCH_CHANNEL_PRIMARY_RADIO);
            break;
        }
        break;
    }
    case eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST: {

        // Wait between retries if needed
        if (std::chrono::steady_clock::now() < m_next_retry_time) {
            break;
        }

        // The task is always started in switch-antenna off state to release
        // the antenna on startup in case of recovery from a crash of the agent,
        // but we must not touch the antenna at all if the feature is not enabled
        // in configuration - not to interfere in case external daemon manages
        // the feature.
        // Skip this case if the feature is disabled and move directly to not-running.
        auto db = AgentDB::get();
        if (!db->device_conf.zwdfs_enable) {
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        // Block switching back 2.4G antenna if its radio is during background scan.
        if (radio_scan_in_progress(eFreqType::FREQ_24G)) {
            break;
        }

        // Block switching back 2.4G antenna while the ZW-DFS interface is down.
        if (!m_zwdfs_ap_enabled) {
            break;
        }

        LOG(DEBUG) << "Sending ZWDFS antenna switch off request";
        auto agent_fd = m_btl_ctx.get_agent_fd();
        if (agent_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
            LOG(DEBUG) << "socket to Agent not found";
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
            break;
        }

        auto request = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST>(m_cmdu_tx);
        if (!request) {
            LOG(ERROR) << "Failed to build message";
            break;
        }

        request->ant_switch_on() = false;

        m_btl_ctx.send_cmdu(agent_fd, m_cmdu_tx);

        constexpr uint8_t ZWDFS_SWITCH_ANT_OFF_RESPONSE_SEC = 3;

        m_zwdfs_fsm_timeout = std::chrono::steady_clock::now() +
                              std::chrono::seconds(ZWDFS_SWITCH_ANT_OFF_RESPONSE_SEC);

        ZWDFS_FSM_MOVE_STATE(eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE);
        break;
    }
    case eZwdfsState::WAIT_FOR_ZWDFS_SWITCH_ANT_OFF_RESPONSE: {
        if (std::chrono::steady_clock::now() > m_zwdfs_fsm_timeout) {
            LOG(ERROR) << "Reached timeout waiting for ZWDFS_SWITCH_ANT_OFF response!";

            if (m_retry_counter >= ZWDFS_FLOW_MAX_RETRIES) {
                LOG(ERROR) << "Too many retries switching off zwdfs antenna ("
                           << int(ZWDFS_FLOW_MAX_RETRIES) << "), aborting.";
                m_next_retry_time = std::chrono::steady_clock::now();
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::NOT_RUNNING);
                break;
            }

            // Retry ZWDFS_SWITCH_ANT_OFF_REQUEST
            ++m_retry_counter;
            LOG(DEBUG) << "zw-dfs flow retry (" << m_retry_counter << "/"
                       << int(ZWDFS_FLOW_MAX_RETRIES) << ")";
            m_next_retry_time = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(ZWDFS_FLOW_DELAY_BETWEEN_RETRIES_MSEC);
            ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_OFF_REQUEST);
            break;
        }
        break;
    }
    default:
        break;
    }
}

ChannelSelectionTask::sSelectedChannel
ChannelSelectionTask::select_best_usable_channel(const std::string &front_radio_iface)
{
    auto db = AgentDB::get();

    sSelectedChannel selected_channel = {};

    auto radio = db->radio(front_radio_iface);
    if (!radio) {
        return sSelectedChannel();
    }

    int32_t best_rank = -1;

    // Initialize the best channel to the current channel, and add the ranking threshold
    // so only channel that has a better rank than the current channel (with threshold),
    // could be selected.
    for (const auto &channel_bw_info : radio->channels_list.at(radio->channel).supported_bw_list) {
        if (channel_bw_info.bandwidth == radio->bandwidth) {
            best_rank                  = channel_bw_info.rank;
            selected_channel.channel   = radio->channel;
            selected_channel.bw        = channel_bw_info.bandwidth;
            selected_channel.dfs_state = radio->channels_list.at(radio->channel).dfs_state;
            selected_channel.rank      = channel_bw_info.rank;
            break;
        }
    }

    if (best_rank == -1) {
        LOG(DEBUG) << "Current channel rank not found! Setting `current rank` as worst rank "
                      "and searching for any other channel";
        best_rank = INT32_MAX;
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

            // Prefer higher bandwidth with a same ranking.
            if (supported_bw.rank == best_rank && supported_bw.bandwidth < selected_channel.bw) {
                continue;
            }

            bool update_best_channel = false;

            auto filter_channel_bw_with_unavailable_overlapping_channel = [&]() {
                auto overlapping_beacon_channels =
                    son::wireless_utils::get_overlapping_beacon_channels(channel,
                                                                         supported_bw.bandwidth);

                // Ignore if one of beacon channels is unavailable.
                for (const auto overlap_ch : overlapping_beacon_channels) {
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

            best_rank                  = supported_bw.rank;
            selected_channel.channel   = channel;
            selected_channel.bw        = supported_bw.bandwidth;
            selected_channel.dfs_state = dfs_state;
            selected_channel.rank      = best_rank;
        }
    }

    return selected_channel;
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
