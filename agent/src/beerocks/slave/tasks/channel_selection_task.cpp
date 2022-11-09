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
 * @return Preference score of the given channel using the given preference map.
 */
uint8_t
get_preference_for_channel(const AgentDB::sRadio::channel_preferences_map &channel_preferences,
                           uint8_t operating_class, uint8_t channel_number)
{
    // Check if channel present in operating class
    if (!son::wireless_utils::is_channel_in_operating_class(operating_class, channel_number)) {
        // Channel is not present in Operating Class, returning Non-Operable
        return (uint8_t)beerocks::eChannelPreferenceRankingConsts::NON_OPERABLE;
    }

    // Check if Operating Class is present in the preference map.
    if (std::find_if(channel_preferences.begin(), channel_preferences.end(),
                     [operating_class](
                         const AgentDB::sRadio::channel_preferences_map::const_reference &iter) {
                         return (iter.first.operating_class == operating_class);
                     }) == channel_preferences.end()) {
        // Preference is not present in the preference map, returning BEST.
        return (uint8_t)beerocks::eChannelPreferenceRankingConsts::BEST;
    }

    for (const auto &preference_iter : channel_preferences) {
        // Check if correct operating class
        if (preference_iter.first.operating_class != operating_class) {
            continue;
        }
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
        // Found the preference for the given channel.
        return preference_iter.first.flags.preference;
    }

    /**
     * If this is reached it means that even though the preference
     * contains the operating class, it does not contain the specific
     * channel in it's channel list.
     * This means that we need to assume that the channel has the
     * highest preference.
     */
    return (uint8_t)beerocks::eChannelPreferenceRankingConsts::BEST;
}

/**
 * @brief Returns the cumulative preference of a given channel.
 * A cumulative preference is calculated by adding the controller's preference and the radio's preference.
 * If either preference is Non-Operable, return Non-Operable.
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
    return (radio_preference + controller_preference);
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

    LOG(DEBUG) << "Received CHANNEL_SELECTION_REQUEST, mid=" << std::hex << mid;

    // Clear previous request, if any.
    m_pending_selection.mid = mid;
    m_pending_selection.requests.clear();

    // Handle TX Power Limit TLV
    for (const auto &tx_power_limit_tlv : cmdu_rx.getClassList<wfa_map::tlvTransmitPowerLimit>()) {
        if (!handle_transmit_power_limit(tx_power_limit_tlv)) {
            LOG(ERROR) << "Failed to handle transmit power limit";
        }
    }

    // Handle Controller's Channel Preference TLV
    for (const auto &channel_preference_tlv :
         cmdu_rx.getClassList<wfa_map::tlvChannelPreference>()) {

        const auto &radio_mac = channel_preference_tlv->radio_uid();
        auto &radio_request   = m_pending_selection.requests[radio_mac];

        if (!store_controller_preference(channel_preference_tlv)) {
            LOG(ERROR) << "Failed to store controller preference!";
            radio_request.response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
                DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES;
            continue;
        }
        if (!check_received_preferences_contain_violation(radio_mac)) {
            LOG(ERROR) << "Failed checking if received preferences contain violation!";
            radio_request.response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
                DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES;
            continue;
        }
        if (!check_is_there_better_channel_than_current(radio_mac)) {
            LOG(ERROR) << "Failed checking if there is a better channel!";
            radio_request.response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
                DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES;
            continue;
        }
    }

    auto db = AgentDB::get();
    // Check if controller is prplMesh.
    if (db->controller_info.prplmesh_controller) {
        // Controller is prplMesh, parse selection extension TLV.
        if (!handle_on_demand_selection_request_extension_tlv(cmdu_rx)) {
            // Failed to parse the VS TLV, no need to stop the
            // Channel-Selection flow since it is not mandatory.
            LOG(WARNING) << "Failed to parse tlvVsOnDemandChannelSelection!";
        }
    }

    // build and send channel response message
    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type CHANNEL_SELECTION_RESPONSE_MESSAGE, has failed";
        return;
    }

    // Build Channel Selection Response TLVs
    // Need to create a ChannelSelectionResponse TLV for each radio
    for (const auto radio : db->get_radios_list()) {
        const auto &radio_mac    = radio->front.iface_mac;
        const auto &request_iter = m_pending_selection.requests.find(radio_mac);
        // Set the response code to DECLINE if, the request for the specific radio does not exist.
        // Otherwise set the response code to what we set in the given request.
        const auto response_code =
            ((request_iter == m_pending_selection.requests.end())
                 ? wfa_map::tlvChannelSelectionResponse::eResponseCode::ACCEPT
                 : request_iter->second.response_code);

        auto channel_selection_response_tlv =
            m_cmdu_tx.addClass<wfa_map::tlvChannelSelectionResponse>();
        if (!channel_selection_response_tlv) {
            LOG(ERROR) << "addClass ieee1905_1::tlvChannelSelectionResponse has failed";
            return;
        }
        channel_selection_response_tlv->radio_uid()     = radio_mac;
        channel_selection_response_tlv->response_code() = response_code;

        LOG(DEBUG) << "Radio " << radio_mac << " is returning " << response_code
                   << " as a response!";
    }
    // Send response back to the sender.
    LOG(DEBUG) << "Sending Channel-Selection-Response to broker";
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, db->controller_info.bridge_mac, db->bridge.mac);

    bool manually_send_operating_report = false;
    // Handle pending Outgoing requests.
    for (auto &request_iter : m_pending_selection.requests) {
        auto &request         = request_iter.second;
        const auto &radio_mac = request_iter.first;
        auto radio            = db->get_radio_by_mac(radio_mac);

        if (!radio) {
            LOG(ERROR) << "Radio " << radio_mac << " does not exist on the db";
            continue;
        }

        // Check if Channel-Switch is needed
        if (!request.channel_switch_needed && !request.power_switch_received) {
            LOG(DEBUG) << "No Channel Switch needed for radio " << radio_mac;
            request.manually_send_operating_report = true;
            manually_send_operating_report         = true;
            continue;
        }

        // Check if ZWDFS if ZWDFS is needed and On-Selection is enabled.
        // if it is needed & enabled set the selected channel and move
        // the ZWDFS-FSM to ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST.
        // If ZWDFS is not needed or is not enabled, perform a regular channel switch.
        if (request.selected_channel.dfs_state == beerocks_message::eDfsState::USABLE) {
            // ZWDFS is needed
            bool zwdfs_enabled = m_zwdfs_ap_enabled && beerocks::utils::compare_zwdfs_flag(
                                                           db->device_conf.zwdfs_flag,
                                                           beerocks::eZWDFS_flags::ON_SELECTION);
            if (zwdfs_enabled) {
                m_selected_channel          = request.selected_channel;
                m_zwdfs_primary_radio_iface = radio->front.iface_name;
                ZWDFS_FSM_MOVE_STATE(eZwdfsState::ZWDFS_SWITCH_ANT_SET_CHANNEL_REQUEST);
                // Channel switch is handled by the ZWDFS flow.
                continue;
            }
            LOG(INFO) << "ZWDFS is needed but disabled. performing a "
                         "regular Channel-Switch request";
        }
        // Perform a channel switch.
        if (!send_channel_switch_request(radio_mac, request)) {
            LOG(ERROR) << "Failed to send Channel-Switch request.";
        }
    }

    if (manually_send_operating_report) {
        // No need to manually send operating channel report message.
        // If a Channel-Switch was requested, a CSA notification
        // will be received, and an operating channel report will
        // be send from it's handler.
        return;
    }
    // build and send operating channel report message
    if (!m_cmdu_tx.create(0, ieee1905_1::eMessageType::OPERATING_CHANNEL_REPORT_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type OPERATING_CHANNEL_REPORT_MESSAGE, has failed";
        return;
    }
    for (const auto radio : db->get_radios_list()) {
        const auto &radio_mac    = radio->front.iface_mac;
        const auto &request_iter = m_pending_selection.requests.find(radio_mac);
        // Normally, when a channel switch is required, a CSA notification
        // will be received with the new channel setting which is when
        // the agent will send the operating channel report.
        // In case of only a tx power limit change, there will still be
        // a CSA notification which will hold the new power limit and also
        // trigger sending the operating channel report.
        // If neither channel switch nor power limit change is required,
        // we need to explicitly send the event.
        if (request_iter == m_pending_selection.requests.end() ||
            request_iter->second.manually_send_operating_report) {
            if (!create_operating_channel_report(radio_mac)) {
                LOG(ERROR) << "Failed creating Operating Channel Report";
                continue;
            }
        }
    }
    // Send response back to the sender.
    LOG(DEBUG) << "Sending Operating-Channel-Report to broker";
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

    bool zwdfs_on_radar, zwdfs_on_selection, pre_cac;
    utils::get_zwdfs_flags(db->device_conf.zwdfs_flag, zwdfs_on_radar, zwdfs_on_selection, pre_cac);

    if (zwdfs_on_radar || zwdfs_on_selection) {
        // Initiate Agent Managed ZWDFS flow.
        if (notification->cs_params().switch_reason == beerocks::CH_SWITCH_REASON_RADAR) {
            if (!zwdfs_on_radar) {
                LOG(INFO) << "ZWDFS On-Radar is not enabled";
                return;
            }
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
    } else {
        LOG(INFO) << "ZWDFS is disabled";
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
        radio->cac_completion_time = m_zwdfs_fsm_timeout;
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

    // Set to true to trigger the Channel Preference Report to the Controller
    m_send_preference_report_after_cac_completion_event = true;

    // Clear the m_pending_preference struct and m_pending_selection struct
    // if there are no pending selection request/preference query
    if (!m_pending_preference.mid && !m_pending_selection.mid) {
        m_pending_preference.mid                                      = 0;
        m_pending_preference.preference_ready[radio->front.iface_mac] = false;
    }

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
    } else if (m_send_preference_report_after_cac_completion_event) {
        build_channel_preference_report(radio_mac);

        if (m_pending_preference.preference_ready[radio_mac]) {
            if (!send_channel_preference_report(cmdu_rx, beerocks_header)) {
                LOG(ERROR) << "Failed to send the CHANNEL_PREFERENCE_REPORT_MESSAGE!";
            }

            // Clear the send preference report flag.
            m_send_preference_report_after_cac_completion_event = false;
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
    auto cac_completion_report_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2CacCompletionReport>();
    if (!cac_completion_report_tlv) {
        LOG(ERROR) << "Failed to create CAC Completion Report TLV";
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

        if (!cac_status_database.add_cac_completion_report_tlv(radio, cac_completion_report_tlv)) {
            LOG(DEBUG) << "Failed to add CAC Completion Report TLV for " << radio->front.iface_mac;
            return false;
        }
    }

    return true;
}

bool ChannelSelectionTask::create_cac_status_report_tlv()
{
    auto cac_status_report_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2CacStatusReport>();
    if (!cac_status_report_tlv) {
        LOG(ERROR) << "Failed to create CAC Status Report TLV";
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

        if (!cac_status_database.add_cac_status_report_tlv(radio, cac_status_report_tlv)) {
            LOG(DEBUG) << "Failed to add CAC Status Report TLV for " << radio_mac;
            return false;
        }
    }

    return true;
}

bool ChannelSelectionTask::handle_transmit_power_limit(
    const std::shared_ptr<wfa_map::tlvTransmitPowerLimit> tx_power_limit_tlv)
{
    const auto &radio_mac             = tx_power_limit_tlv->radio_uid();
    const auto new_tx_power_limit_dbm = tx_power_limit_tlv->transmit_power_limit_dbm();

    auto &radio_request = m_pending_selection.requests[radio_mac];

    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    LOG(DEBUG) << std::dec << "received tlvTransmitPowerLimit " << (int)new_tx_power_limit_dbm;
    /**
     * Currently it is assumed that if a new TX Power Limit was requested we need to send it to
     * the Agent without any additional validation.
     * 
     * In the outgoing request, set the channel & bandwidth to that of the current radio.
     */
    radio_request.outgoing_request.channel        = radio->channel;
    radio_request.outgoing_request.bandwidth      = radio->bandwidth;
    radio_request.outgoing_request.tx_limit       = new_tx_power_limit_dbm;
    radio_request.outgoing_request.tx_limit_valid = true;
    radio_request.power_switch_received           = true;

    return true;
}

bool ChannelSelectionTask::store_controller_preference(
    const std::shared_ptr<wfa_map::tlvChannelPreference> channel_preference_tlv)
{
    const auto &radio_mac = channel_preference_tlv->radio_uid();
    auto radio            = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    // Get & Clear the previous channel preferences.
    auto &controller_preferences = m_pending_selection.requests[radio_mac].controller_preferences;
    controller_preferences.clear();

    std::stringstream ss;
    ss << "Parsing Controller's Channel Preference TLV:" << std::endl;

    for (int oc_idx = 0; oc_idx < channel_preference_tlv->operating_classes_list_length();
         oc_idx++) {
        auto operating_class_tuple = channel_preference_tlv->operating_classes_list(oc_idx);
        if (!std::get<0>(operating_class_tuple)) {
            LOG(ERROR) << "getting operating class entry has failed!";
            return false;
        }
        auto &op_class_channels    = std::get<1>(operating_class_tuple);
        const auto operating_class = op_class_channels.operating_class();
        const auto preference      = op_class_channels.flags().preference;
        const auto reason_code     = op_class_channels.flags().reason_code;

        auto channel_preference =
            AgentDB::sChannelPreference(operating_class, op_class_channels.flags());
        auto &channels_set = controller_preferences[channel_preference];

        ss << "Operating class=" << +operating_class << ", preference=" << +preference
           << ", reason=" << +reason_code << ", channel_list={";

        for (int ch_idx = 0; ch_idx < op_class_channels.channel_list_length(); ch_idx++) {
            // Get channel
            auto channel_ptr = op_class_channels.channel_list(ch_idx);
            if (!channel_ptr) {
                LOG(ERROR) << "getting channel entry has failed!";
                return false;
            }
            auto channel = *channel_ptr;

            if (!son::wireless_utils::is_channel_in_operating_class(operating_class, channel)) {
                LOG(ERROR) << "Channel " << (int)channel << " invalid for operating class "
                           << (int)operating_class;
                return false;
            }

            ss << (int)channel << " ";
            channels_set.insert(channel);
        }
        ss.seekp(-1, std::ios_base::end); // Remove last space in string-stream
        ss << "}" << std::endl;
    }

    LOG(DEBUG) << ss.str();
    return true;
}

bool ChannelSelectionTask::check_received_preferences_contain_violation(const sMacAddr &radio_mac)
{
    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    auto &radio_request              = m_pending_selection.requests[radio_mac];
    const auto &received_preferences = radio_request.controller_preferences;

    for (const auto &preference_iter : received_preferences) {
        const auto operating_class       = preference_iter.first.operating_class;
        const auto controller_preference = preference_iter.first.flags.preference;

        if (controller_preference == 0) {
            // Skip Operating-Class set that the controller report as Non-Operable.
            continue;
        }

        for (const auto channel : preference_iter.second) {
            const auto radio_preference =
                get_preference_for_channel(radio->channel_preferences, operating_class, channel);
            if (radio_preference == 0) {
                LOG(ERROR) << "[" << channel << "," << operating_class
                           << "] is non-operational on radio " << radio_mac;
                radio_request.response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
                    DECLINE_VIOLATES_CURRENT_PREFERENCES;
                return true; // Returning true because we found a violation.
            }
        }
    }
    // No violations were found.
    return true;
}

bool ChannelSelectionTask::check_is_there_better_channel_than_current(const sMacAddr &radio_mac)
{
    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    beerocks::message::sWifiChannel channel(radio->channel, radio->bandwidth);
    const auto operating_class    = son::wireless_utils::get_operating_class_by_channel(channel);
    auto &radio_request           = m_pending_selection.requests[radio_mac];
    const auto current_preference = get_cumulative_preference(
        radio, radio_request.controller_preferences, operating_class, radio->channel);

    LOG(DEBUG) << "Current Channel is [" << (int)channel.channel << "-" << (int)operating_class
               << "("
               << utils::convert_bandwidth_to_int(
                      beerocks::eWiFiBandwidth(channel.channel_bandwidth))
               << "MHz)] and has a cumulative preference score of " << (int)current_preference;

    /**
     * Find the next best channel.
     * If that channel is not restricted by the agent's preferences.
     * And is better then our currect channel.
     * Switch to that channel.
     */
    sSelectedChannel selected_channel =
        select_next_channel(radio_mac, radio_request.controller_preferences);
    if (selected_channel.channel == 0) {
        LOG(ERROR) << "Could not find a better channel!";
        radio_request.response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
            DECLINE_VIOLATES_CURRENT_PREFERENCES;
        return false;
    }

    LOG(DEBUG) << "Next best channel " << (int)selected_channel.channel << "-"
               << (int)selected_channel.operating_class << " bandwidth: "
               << beerocks::utils::convert_bandwidth_to_int(
                      beerocks::eWiFiBandwidth(selected_channel.bw))
               << " has a preference score of " << (int)selected_channel.preference_score
               << " and a DFS state of " << (int)selected_channel.dfs_state << ".";

    // First validate whether we already operate on the best channel or selected channel.
    if (radio->channel == selected_channel.channel && radio->bandwidth == selected_channel.bw) {

        LOG(DEBUG) << "Already operating on channel: " << (int)selected_channel.channel
                   << " with bandwidth: "
                   << beerocks::utils::convert_bandwidth_to_int(
                          beerocks::eWiFiBandwidth(selected_channel.bw))
                   << ".";

        radio_request.channel_switch_needed = false;
        return true;
    }

    if (current_preference > selected_channel.preference_score) {
        LOG(DEBUG) << "Currect channel is better than the next best channel, no need "
                      "to switch";
        return true;
    }

    radio_request.selected_channel           = selected_channel;
    radio_request.outgoing_request.channel   = selected_channel.channel;
    radio_request.outgoing_request.bandwidth = selected_channel.bw;
    radio_request.channel_switch_needed      = true;

    return true;
}

ChannelSelectionTask::sSelectedChannel ChannelSelectionTask::select_next_channel(
    const sMacAddr &radio_mac,
    const AgentDB::sRadio::channel_preferences_map &controller_preferences)
{
    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(DEBUG) << "Radio " << radio_mac << " does not exist on the db";
        return sSelectedChannel();
    }

    auto find_best_beacon_channel =
        [&](const uint8_t primary_channel, const beerocks::eWiFiBandwidth bandwidth,
            const uint8_t operating_class) -> std::pair<uint8_t, uint8_t> {
        const auto beacon_channels =
            son::wireless_utils::center_channel_5g_to_beacon_channels(primary_channel, bandwidth);

        uint8_t best_bcn_pref = 0;
        uint8_t best_bcn_chan = 0;

        for (const auto beacon_channel : beacon_channels) {

            // Get the 20Mhz operating class for the beacon channel
            const auto operating_class_20Mhz = son::wireless_utils::get_operating_class_by_channel(
                message::sWifiChannel(beacon_channel, eWiFiBandwidth::BANDWIDTH_20));

            // Get the cumulative channel preference for the beacon channel.
            auto beacon_preference = get_cumulative_preference(
                radio, controller_preferences, operating_class_20Mhz, beacon_channel);
            if (beacon_preference == 0) {
                LOG(ERROR) << "Channel #" << beacon_channel << " in Class #"
                           << operating_class_20Mhz << " is non-operable";
            } else if (best_bcn_pref < beacon_preference) {
                // Set as the highest preference in the beacon channels
                best_bcn_pref = beacon_preference;
                best_bcn_chan = beacon_channel;
            }
        }

        // Get the 20Mhz operating class for the beacon channel
        const auto operating_class_20Mhz = son::wireless_utils::get_operating_class_by_channel(
            message::sWifiChannel(best_bcn_chan, eWiFiBandwidth::BANDWIDTH_20));

        // Get the radio preference for the best beacon
        auto bcn_radio_pref = get_preference_for_channel(radio->channel_preferences,
                                                         operating_class_20Mhz, best_bcn_chan);
        // Get the controller preference for the central channel
        auto bcn_controller_pref =
            get_preference_for_channel(controller_preferences, operating_class, primary_channel);
        // Return the combination of the beacon's radio's preference with the primary's controller's preference.
        return std::make_pair(best_bcn_chan, (bcn_controller_pref + bcn_radio_pref));
    };

    const auto &radio_request        = m_pending_selection.requests[radio_mac];
    const auto &received_preferences = radio_request.controller_preferences;

    sSelectedChannel best_channel = {};

    for (const auto &channel_iter : radio->channels_list) {
        const auto channel_number = channel_iter.first;
        const auto &channel_info  = channel_iter.second;

        if (channel_info.dfs_state == beerocks_message::eDfsState::UNAVAILABLE) {
            // Skipping UNAVAILABLE channels.
            continue;
        }

        for (auto &bw_info : channel_info.supported_bw_list) {
            const auto bandwidth       = bw_info.bandwidth;
            const auto operating_class = son::wireless_utils::get_operating_class_by_channel(
                message::sWifiChannel(channel_number, bandwidth));

            if (operating_class == 0) {
                // Skip invalid operating class
                continue;
            }

            auto primary_channel = channel_number;
            if (son::wireless_utils::is_operating_class_using_central_channel(operating_class)) {
                auto source_channel_it =
                    son::wireless_utils::channels_table_5g.find(channel_number);
                if (source_channel_it == son::wireless_utils::channels_table_5g.end()) {
                    LOG(WARNING) << "Couldn't find source channel " << channel_number
                                 << " for overlapping channels";
                    continue;
                }
                primary_channel = source_channel_it->second.at(bandwidth).center_channel;
            }

            const auto cumulative_preference = get_cumulative_preference(
                radio, received_preferences, operating_class, primary_channel);
            if (cumulative_preference == 0) {
                // Either radio or controller preference is Non-Operable, skipping
                continue;
            }

            /** According to the MultiAP EasyMesh specifications R4 Appendix A.3.5
             * The Multi-AP Controller can indicate its preference for a specific primary channel
             * for a greater than 40 MHz (e.g., 80 MHz, 160 MHz) operation by including two
             * operating classes in the Channel Preference TLV, one for the larger bandwidth and 
             * one for the 20 MHz primary channel. For example, include opclass 128 with channel
             * numbers 58, 106, 122, 138, and 155 with preference values 1 (implying 42 is the
             * most preferred) and opclass 115 with channel numbers 36, 44, and 48 with
             * preferences 1 (implying 40 is the most preferred) to indicate to the Multi-AP
             * Agent that 80 MHz operation with channel number 40 as the Primary Channel is the
             * most preferred.
             *
             * This means that for bandwidths 80M & 160M we need to choose best beacon
             * channel according to 20M ranking.
             * After we have found the best beacon we need to override the higher bandwidth's
             * preference score so that our higher bandwidth selected channel will be considered
             * the best primary channel.
             */
            //
            auto primary_preference = cumulative_preference;
            if (bandwidth >= eWiFiBandwidth::BANDWIDTH_80) {
                LOG(INFO) << "[" << primary_channel << "-" << operating_class << "("
                          << utils::convert_bandwidth_to_int(bandwidth)
                          << "MHz)] uses a beacon channel.";
                auto best_channel_pair =
                    find_best_beacon_channel(primary_channel, bandwidth, operating_class);
                // For any fail case, we should switch to the selected primary channel
                if (best_channel_pair.first != 0) {
                    primary_channel    = best_channel_pair.first;
                    primary_preference = best_channel_pair.second;
                }
            }

            LOG(INFO) << "[" << primary_channel << "-" << operating_class << "("
                      << utils::convert_bandwidth_to_int(bandwidth)
                      << "MHz)] has a preference score of " << primary_preference;

            if (primary_preference < best_channel.preference_score) {
                // Found preference is lower then best, skip.
                continue;
            } else if (primary_preference == best_channel.preference_score) {
                // On a same preference, prefer a higher bandwidth.
                if (bandwidth <= best_channel.bw) {
                    // Found bandwidth is lower or equal to the best, skip.
                    continue;
                }
            }

            LOG(INFO) << "[" << primary_channel << "-" << operating_class << "("
                      << utils::convert_bandwidth_to_int(bandwidth)
                      << "MHz)] is the new Best-Channel";
            // Override selected channel
            best_channel.channel          = primary_channel;
            best_channel.preference_score = primary_preference;
            best_channel.operating_class  = operating_class;
            best_channel.bw               = bandwidth;
            best_channel.dfs_state        = channel_info.dfs_state;
        }
    }

    if (best_channel.preference_score == 0) {
        LOG(ERROR) << "Could not find a suitable channel";
        return sSelectedChannel();
    }

    // Return our new selected channel.
    return best_channel;
}

bool ChannelSelectionTask::handle_on_demand_selection_request_extension_tlv(
    ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto beerocks_header = beerocks::message_com::parse_intel_vs_message(cmdu_rx);
    if (!beerocks_header) {
        LOG(ERROR) << "expecting beerocks_message::tlvVsOnDemandChannelSelection";
        return false;
    }

    auto on_demand_requests =
        beerocks_header->addClass<beerocks_message::tlvVsOnDemandChannelSelection>();
    if (!on_demand_requests) {
        LOG(ERROR) << "addClass beerocks_message::tlvVsOnDemandChannelSelection failed";
        return false;
    }

    const auto &radio_mac = on_demand_requests->radio_mac();
    const auto csa_count  = on_demand_requests->CSA_count();

    const auto pending_request_iter = m_pending_selection.requests.find(radio_mac);
    if (pending_request_iter == m_pending_selection.requests.end()) {
        LOG(ERROR) << "There is no pending Channel-Selection request that matches " << radio_mac;
        return false;
    }

    // Found the request
    auto &pending_request = pending_request_iter->second;

    LOG(INFO) << "Received an On-Demand Channel-Selection request with a CSA count of "
              << csa_count;

    // Force a channel switch
    if (pending_request.channel_switch_needed) {
        pending_request.outgoing_request.CSA_count = csa_count;
    }
    return true;
}

bool ChannelSelectionTask::send_channel_switch_request(
    const sMacAddr &radio_mac, const sIncomingChannelSelectionRequest &request)
{
    auto request_msg = message_com::create_vs_message<
        beerocks_message::cACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START>(m_cmdu_tx);

    if (!request_msg) {
        LOG(ERROR) << "Failed to build message";
        return false;
    }

    request_msg->cs_params().channel   = request.outgoing_request.channel;
    request_msg->cs_params().bandwidth = request.outgoing_request.bandwidth;
    request_msg->cs_params().csa_count = request.outgoing_request.CSA_count;

    if (request.outgoing_request.bandwidth >= beerocks::eWiFiBandwidth::BANDWIDTH_40) {
        // Because we want to switch to a bandwidth that is greater then 20Mhz,
        // We need to find the central frequancy and set it to the VHT param.
        const auto beacon_channel = request.outgoing_request.channel;
        const auto bandwidth      = request.outgoing_request.bandwidth;
        request_msg->cs_params().vht_center_frequency =
            son::wireless_utils::get_vht_central_frequency(beacon_channel, bandwidth);
    } else {
        request_msg->cs_params().vht_center_frequency =
            son::wireless_utils::channel_to_freq(request.outgoing_request.channel);
    }

    request_msg->tx_limit()       = request.outgoing_request.tx_limit;
    request_msg->tx_limit_valid() = request.outgoing_request.tx_limit_valid;

    auto agent_fd = m_btl_ctx.get_agent_fd();
    if (agent_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
        LOG(ERROR) << "socket to Agent not found";
        return false;
    }

    auto action_header         = message_com::get_beerocks_header(m_cmdu_tx)->actionhdr();
    action_header->radio_mac() = radio_mac;

    LOG(DEBUG) << "Sending a CHANNEL_SWITCH request to radio " << radio_mac
               << " with the following paramenters:" << std::endl
               << "- Channel: " << request_msg->cs_params().channel << std::endl
               << "- bandwidth: " << request_msg->cs_params().bandwidth << std::endl
               << "- CSA count: " << request_msg->cs_params().csa_count << std::endl
               << "- TX limit: " << (int)request_msg->tx_limit() << std::endl
               << "- TX limit valid: " << (request_msg->tx_limit_valid() ? "True" : "False");

    m_btl_ctx.send_cmdu(agent_fd, m_cmdu_tx);
    return true;
}

bool ChannelSelectionTask::create_operating_channel_report(const sMacAddr &radio_mac)
{
    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    auto operating_channel_report_tlv = m_cmdu_tx.addClass<wfa_map::tlvOperatingChannelReport>();
    if (!operating_channel_report_tlv) {
        LOG(ERROR) << "addClass ieee1905_1::operating_channel_report_tlv has failed";
        return false;
    }
    operating_channel_report_tlv->radio_uid() = radio_mac;

    auto op_classes_list = operating_channel_report_tlv->alloc_operating_classes_list();
    if (!op_classes_list) {
        LOG(ERROR) << "alloc_operating_classes_list() has failed!";
        return false;
    }

    auto operating_class_entry_tuple = operating_channel_report_tlv->operating_classes_list(0);
    if (!std::get<0>(operating_class_entry_tuple)) {
        LOG(ERROR) << "getting operating class entry has failed!";
        return false;
    }

    auto &operating_class_entry = std::get<1>(operating_class_entry_tuple);
    beerocks::message::sWifiChannel channel;
    channel.channel_bandwidth = radio->bandwidth;
    channel.channel           = radio->channel;
    auto center_channel       = son::wireless_utils::freq_to_channel(radio->vht_center_frequency);
    auto operating_class      = son::wireless_utils::get_operating_class_by_channel(channel);

    operating_class_entry.operating_class = operating_class;
    // operating classes 128,129,130 use center channel **unlike the other classes** (See Table
    // E-4 in 802.11 spec)
    operating_class_entry.channel_number =
        son::wireless_utils::is_operating_class_using_central_channel(operating_class)
            ? center_channel
            : channel.channel;
    operating_channel_report_tlv->current_transmit_power() = radio->tx_power_dB;

    LOG(DEBUG) << "Created Operating Channel Report TLV";
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
            LOG(INFO) << "Channel " << m_selected_channel.channel
                      << " with bw=" << m_selected_channel.bw
                      << " and dfs_state=" << m_selected_channel.dfs_state
                      << " has better rank than current channel, but did not pass the ranking "
                         "threshold="
                      << db->device_conf.best_channel_rank_threshold
                      << ", Current channel is selected.";
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

        auto radio = AgentDB::get()->radio(m_zwdfs_primary_radio_iface);
        if (!radio) {
            break;
        }

        if (radio_scan_in_progress(radio->freq_type)) {
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
        if (!utils::compare_zwdfs_flag(db->device_conf.zwdfs_flag, beerocks::eZWDFS_flags::ALL)) {
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
                    son::wireless_utils::get_overlapping_5g_beacon_channels(channel,
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
