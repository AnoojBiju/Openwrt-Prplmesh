/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "vbss_task.h"

#include "../src/beerocks/master/son_actions.h"
#include <tlvf/wfa_map/tlvApRadioVbssCapabilities.h>
#include <tlvf/wfa_map/tlvClientInfo.h>
#include <tlvf/wfa_map/tlvClientSecurityContext.h>
#include <tlvf/wfa_map/tlvTriggerChannelSwitchAnnouncement.h>
#include <tlvf/wfa_map/tlvVbssConfigurationReport.h>
#include <tlvf/wfa_map/tlvVirtualBssEvent.h>

vbss_task::vbss_task(son::db &database, task_pool &tasks, const std::string &task_name_)
    : task(task_name_), m_database(database), m_tasks(tasks)
{
    if (database.get_vbss_task_id() != db::TASK_ID_NOT_FOUND) {
        database.assign_vbss_task_id(id);
    }
}

/*
 Virtual BSS Capabilities Response
    - AP Radio VBSS Capabilities TLV

 Virtual BSS Response
    - Virtual BSS Event TLV

 Client Security Context Response
    - Client Info TLV
    - Client Security Context TLV

 Trigger Channel Switch Announcement Response
    - Client Info TLV
    - Trigger Channel Switch Announcement TLV

 Virtual VBSS Move Preparation Response
    - Client Info TLV

 Virtual BSS Move Cancel Response
    - Client Info TLV

-----------------------------------------------

 1905 Topology Response Message
    - VBSS Configuration Report TLV
    - ...

 1905 AP-Autoconfiguration WSC message
    - AP Radio VBSS Capabilities TLV
    - ...

 BSS Configuration Request
    - AP Radio VBSS Capabilities TLV
    - ...
*/
bool vbss_task::handle_ieee1905_1_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::VIRTUAL_BSS_CAPABILITIES_REPONSE_MESSAGE:
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::VIRTUAL_BSS_RESPONSE_MESSAGE:
        return handle_vbss_event_response(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::CLIENT_SECURITY_CONTEXT_RESPONSE_MESSAGE:
        return handle_client_security_ctx_resp(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::TRIGGER_CHANNEL_SWITCH_ANNOUNCEMENT_RESPONSE_MESSAGE:
        return handle_trigger_chan_switch_announce_resp(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::VIRTUAL_BSS_MOVE_PREPARATION_RESPONSE_MESSAGE:
        return handle_move_response_msg(src_mac, cmdu_rx, false);
    case ieee1905_1::eMessageType::VIRTUAL_BSS_MOVE_CANCEL_RESPONSE_MESSAGE:
        return handle_move_response_msg(src_mac, cmdu_rx, true);
    case ieee1905_1::eMessageType::TOPOLOGY_RESPONSE_MESSAGE:
        return handle_top_response_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_WSC_MESSAGE:
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_REQUEST_MESSAGE:
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    default:
        TASK_LOG(ERROR) << "Unknown CMDU message type: " << std::hex
                        << int(cmdu_rx.getMessageType());
        return false;
    }
}

void vbss_task::work() {}

void vbss_task::handle_event(int event_enum_value, void *event_obj)
{
    if (!event_obj) {
        TASK_LOG(ERROR) << "Could not process event type (" << event_enum_value
                        << ")! event_obj == nullptr";
        return;
    }

    switch (event_enum_value) {
    case eEventType::MOVE: {
        auto move_event = reinterpret_cast<sMoveEvent *>(event_obj);
        LOG(INFO) << "VBSS Task recieved a MOVE event. Starting move process for client \""
                  << move_event->client_vbss.client_mac << "\"";
        handle_move_client_event(*move_event);
        break;
    }
    case eEventType::CREATE: {
        auto create_event = reinterpret_cast<sCreationEvent *>(event_obj);
        LOG(INFO)
            << "VBSS Task received a CREATE event. Starting vbss creation process for client \""
            << create_event->client_vbss.client_mac << "\"";
        handle_vbss_creation_event(*create_event);
        break;
    }
    case eEventType::DESTROY: {
        auto destroy_event = reinterpret_cast<sDestructionEvent *>(event_obj);
        LOG(INFO)
            << "VBSS Task received a DESTROY event. Starting vbss destruction process for client \""
            << destroy_event->client_vbss.client_mac << "\"";
        handle_vbss_destruction_event(*destroy_event);
        break;
    }
    default:
        LOG(WARNING) << "VBSS Task recieved an unhandled event type (" << event_enum_value << ")";
        break;
    }
}

bool vbss_task::handle_move_client_event(const sMoveEvent &move_event)
{
    vbss::sClientVBSS client_vbss = move_event.client_vbss;
    sMacAddr client_mac           = client_vbss.client_mac;

    auto existing_move = active_moves.get(client_vbss.vbssid);
    if (existing_move) {
        LOG(ERROR) << "Could not start a new move for client with MAC address " << client_mac
                   << "! Move already in progress for VBSSID " << client_vbss.vbssid
                   << " (From radio " << existing_move->client_vbss.current_connected_ruid
                   << " to radio " << existing_move->dest_ruid << ")";
        return false;
    }

    auto agent = m_database.get_agent_by_radio_uid(client_vbss.current_connected_ruid);
    if (agent == nullptr) {
        LOG(ERROR) << "Could not start a new move for client with MAC address " << client_mac
                   << "! Could not find agent for radio uid " << client_vbss.current_connected_ruid;
        return false;
    }

    // Add a new sMoveEvent to the mac_map with the new state CLIENT_SEC_CTX (Client Security Context Request)
    // which is the first step of the move process
    active_moves.add(client_vbss.vbssid, client_vbss, move_event.dest_ruid, move_event.ssid,
                     move_event.password);

    sMacAddr agent_mac = agent->al_mac;

    if (!vbss::vbss_actions::send_client_security_ctx_request(agent_mac, client_vbss, m_database)) {
        LOG(ERROR) << "Could not start a new move for client with MAC address " << client_mac
                   << "! Client Security Context Request failed to send!";
        return false;
    }

    // At this point, the move request process has started,
    // and the following requests will be sent by the corresponding response handlers.
    return true;
}

bool vbss_task::handle_vbss_creation_event(const sCreationEvent &create_event)
{
    vbss::sClientVBSS client_vbss = create_event.client_vbss;
    sMacAddr client_mac           = client_vbss.client_mac;

    // You cannot create a VBSS via this method while a move for this VBSSID is ongoing
    auto existing_move = active_moves.get(client_vbss.vbssid);
    if (existing_move) {
        LOG(ERROR) << "Could not start VBSS creation for client with MAC address " << client_mac
                   << "! Move already in progress for VBSSID " << client_vbss.vbssid
                   << " (From radio " << existing_move->client_vbss.current_connected_ruid
                   << " to radio " << existing_move->dest_ruid << ")";
        return false;
    }

    auto existing_creation = active_creation_events.get(client_vbss.vbssid);
    if (existing_creation) {
        LOG(ERROR) << "Could not start VBSS creation for client with MAC address " << client_mac
                   << "! Creation already in progress for VBSSID " << client_vbss.vbssid
                   << " on the radio with UID " << existing_creation->dest_ruid;
        return false;
    }

    auto agent = m_database.get_agent_by_radio_uid(client_vbss.current_connected_ruid);
    if (!agent) {
        LOG(ERROR) << "Could not start VBSS creation for client with MAC address " << client_mac
                   << "! Could not find agent for radio uid " << client_vbss.current_connected_ruid;
        return false;
    }

    active_creation_events.add(client_vbss.vbssid, client_vbss, create_event.dest_ruid,
                               create_event.ssid, create_event.password);

    sMacAddr agent_mac = agent->al_mac;

    if (client_vbss.client_is_associated) {
        // Client is already associated, Must have the Security Context to create a VBSS
        if (!vbss::vbss_actions::send_client_security_ctx_request(agent_mac, client_vbss,
                                                                  m_database)) {
            LOG(ERROR) << "Could not start VBSS creation for client with MAC address " << client_mac
                       << "! Client Security Context Request failed to send!";
            return false;
        }
        return true;
    }

    // Client is not associated, just request VBSS creation
    if (!vbss::vbss_actions::create_vbss(client_vbss, create_event.dest_ruid, create_event.ssid,
                                         create_event.password, nullptr, m_database)) {
        LOG(ERROR) << "Could not start VBSS creation for client with MAC address " << client_mac
                   << "! Create VBSS Request failed to send!";
        return false;
    }

    return true;
}

bool vbss_task::handle_vbss_destruction_event(const sDestructionEvent &destroy_event)
{

    vbss::sClientVBSS client_vbss = destroy_event.client_vbss;
    sMacAddr client_mac           = client_vbss.client_mac;

    // You cannot destroy a VBSS via this method while a move for this VBSSID is ongoing
    auto existing_move = active_moves.get(client_vbss.vbssid);
    if (existing_move) {
        LOG(ERROR) << "Could not start VBSS destruction for client with MAC address " << client_mac
                   << "! Move already in progress for VBSSID " << existing_move->client_vbss.vbssid
                   << " (From radio " << existing_move->client_vbss.current_connected_ruid
                   << " to radio " << existing_move->dest_ruid << ")";
        return false;
    }

    auto existing_destruction = active_destruction_events.get(destroy_event.client_vbss.vbssid);
    if (existing_destruction) {
        LOG(ERROR) << "Could not start VBSS destruction for client with MAC address " << client_mac
                   << "! Destruction already in progress for VBSSID "
                   << destroy_event.client_vbss.vbssid << " on the radio with UID "
                   << existing_destruction->client_vbss.current_connected_ruid;
        return false;
    }

    active_destruction_events.add(client_vbss.vbssid, client_vbss,
                                  destroy_event.should_disassociate);

    if (!vbss::vbss_actions::destroy_vbss(client_vbss, destroy_event.should_disassociate,
                                          m_database)) {
        LOG(ERROR) << "Could not start VBSS destruction for client with MAC address " << client_mac
                   << "! Destruction request failed!";
        return false;
    }
    return true;
}

bool vbss_task::handle_ap_radio_vbss_caps_msg(const sMacAddr &src_mac,
                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto ap_vbss_caps_tlv_list = cmdu_rx.getClassList<wfa_map::ApRadioVbssCapabilities>();
    if (ap_vbss_caps_tlv_list.empty()) {
        TASK_LOG(ERROR) << "BSS Configuration Request CMDU mid=" << std::hex
                        << cmdu_rx.getMessageId()
                        << " does not have AP Radio VBSS Capabilities TLV";
        return false;
    }

    // A TLV is returned for each radio that supports VBSS, handle all of them
    beerocks::mac_map<vbss::sAPRadioVBSSCapabilities> ruid_caps_map;

    for (const auto &ap_vbss_caps_tlv : ap_vbss_caps_tlv_list) {
        vbss::sAPRadioVBSSCapabilities ap_radio_caps = {};

        ap_radio_caps.max_vbss              = ap_vbss_caps_tlv->max_vbss();
        ap_radio_caps.vbsses_subtract       = ap_vbss_caps_tlv->vbss_settings().vbsss_subtract;
        ap_radio_caps.apply_vbssid_restrict = ap_vbss_caps_tlv->vbss_settings().vbssid_restrictions;
        ap_radio_caps.apply_vbssid_match_mask_restrict =
            ap_vbss_caps_tlv->vbss_settings().vbssid_match_and_mask_restrictions;
        ap_radio_caps.apply_fixed_bits_restrict =
            ap_vbss_caps_tlv->vbss_settings().fixed_bit_restrictions;
        ap_radio_caps.fixed_bits_mask  = ap_vbss_caps_tlv->fixed_bits_mask();
        ap_radio_caps.fixed_bits_value = ap_vbss_caps_tlv->fixed_bits_value();

        ruid_caps_map.add(ap_vbss_caps_tlv->radio_uid(), ap_radio_caps);
    }

    //TODO: Send to VBSSManager (include src_mac = agent_mac)

    return true;
}
bool vbss_task::handle_move_response_msg(const sMacAddr &src_mac,
                                         ieee1905_1::CmduMessageRx &cmdu_rx, bool is_cancelled)
{

    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    std::string msg_desc = is_cancelled ? "Move Cancel" : "Move Preparation";

    if (!client_info_tlv) {
        LOG(ERROR) << msg_desc << " Response did not contain a Client Info TLV!";
        return false;
    }

    sMacAddr client_mac = client_info_tlv->client_mac();
    sMacAddr bssid      = client_info_tlv->bssid();

    LOG(INFO) << "Recieved " << msg_desc << "Response for Client MAC " << client_mac
              << " and BSSID " << bssid;

    auto existing_move = get_matching_active_move(bssid, eMoveProcessState::VBSS_MOVE_PREP);
    if (existing_move != nullptr && !is_cancelled) {
        // Move exists for VBSSID and is in response to a MOVE_PREP request
        existing_move->state = eMoveProcessState::VBSS_CREATION;
        if (!vbss::vbss_actions::create_vbss(existing_move->client_vbss, existing_move->dest_ruid,
                                             existing_move->ssid, existing_move->password,
                                             existing_move->sec_ctx_info.get(), m_database)) {
            LOG(ERROR) << "Failed to send Create VBSS request during move operation!";
            return false;
        }
        return true;
    }

    return true;
}

bool vbss_task::handle_trigger_chan_switch_announce_resp(const sMacAddr &src_mac,
                                                         ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();

    if (!client_info_tlv) {
        LOG(ERROR)
            << "Trigger Channel Switch Announcement Response did not contain the Client Info TLV!";
        return false;
    }

    sMacAddr client_mac = client_info_tlv->client_mac();
    sMacAddr bssid      = client_info_tlv->bssid();

    auto channel_switch_tlv = cmdu_rx.getClass<wfa_map::TriggerChannelSwitchAnnouncement>();
    if (!channel_switch_tlv) {
        LOG(ERROR) << "Trigger Channel Switch Announcement Response did not contain the Trigger "
                      "Channel Switch Announcement TLV!";
        return false;
    }

    uint8_t csa_channel = channel_switch_tlv->csa_channel();
    uint8_t op_class    = channel_switch_tlv->opclass();

    LOG(INFO) << "Recieved Trigger Channel Switch Announcement Response for Client " << client_mac
              << ", Channel #" << csa_channel << " and Op Class (" << op_class << ")";

    auto existing_move = get_matching_active_move(bssid, eMoveProcessState::TRIGGER_CHANNEL_SWITCH);
    if (existing_move != nullptr) {
        // Recieved Trigger Channel Switch Announcement during move
        // Destroy existing VBSS now that channel has been switched
        existing_move->state = eMoveProcessState::VBSS_DESTRUCTION;
        if (!vbss::vbss_actions::destroy_vbss(existing_move->client_vbss, false, m_database)) {
            LOG(ERROR) << "Move creation succeeded, but vbss destruction request to radio "
                       << existing_move->client_vbss.current_connected_ruid << " failed to send!";
            return false;
        }
        return true;
    }

    return true;
}

bool vbss_task::handle_vbss_event_response(const sMacAddr &src_mac,
                                           ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto vbss_event_tlv = cmdu_rx.getClass<wfa_map::VirtualBssEvent>();

    if (!vbss_event_tlv) {
        LOG(ERROR) << "VBSS Response does not contain a VBSS Event TLV!";
        return false;
    }
    sMacAddr ruid     = vbss_event_tlv->radio_uid();
    sMacAddr vbssid   = vbss_event_tlv->bssid();
    bool is_succeeded = vbss_event_tlv->success();

    auto existing_creation = active_creation_events.get(vbssid);
    if (existing_creation) {
        // Recieved the response to an active creation request

        active_creation_events.erase(vbssid);
        if (!is_succeeded) {
            LOG(ERROR) << "Virtual BSS Creation failed on destination radio " << ruid
                       << "! Creation event failed";
            return false;
        }
        //TODO: Add VBSSes to DM

        return true;
    }

    auto existing_destruction = active_destruction_events.get(vbssid);
    if (existing_destruction) {
        // Recieved the response to an active destruction request
        active_destruction_events.erase(vbssid);
        if (!is_succeeded) {
            LOG(ERROR) << "Virtual BSS Destruction failed on destination radio " << ruid
                       << "! Destroy event failed";
            return false;
        }
        //TODO: Add VBSSes to DM

        return true;
    }

    auto existing_move = get_matching_active_move(vbssid, eMoveProcessState::VBSS_CREATION);
    if (existing_move) {
        // Received creation request response during a move

        sMacAddr src_ruid = existing_move->client_vbss.current_connected_ruid;
        auto src_agent    = m_database.get_agent_by_radio_uid(src_ruid);

        if (!src_agent) {
            LOG(ERROR) << "Could not get agent for currently connected radio UID " << src_ruid
                       << " does not exist!";
            return false;
        }
        sMacAddr agent_mac = src_agent->al_mac;

        if (!is_succeeded) {
            // Creation failed, send move cancel request
            LOG(INFO) << "Virtual BSS Creation failed on destination radio " << ruid
                      << "! Sending Move Cancel request to currently connected radio";

            existing_move->state = eMoveProcessState::VBSS_MOVE_CANCEL;

            if (vbss::vbss_actions::send_move_cancel_request(agent_mac, existing_move->client_vbss,
                                                             m_database)) {
                LOG(ERROR) << "Failed to send Move Cancel Request!";
                return false;
            }
            return true; // Even though the creation failed, the handling of the request was successful
        }
        // Creation Succeeded, send trigger switch announcement request (if required)
        uint8_t channel, opclass;
        if (should_trigger_channel_switch(src_ruid, existing_move->dest_ruid, channel, opclass)) {

            existing_move->state = eMoveProcessState::TRIGGER_CHANNEL_SWITCH;
            if (vbss::vbss_actions::send_trigger_channel_switch_announcement(
                    agent_mac, channel, opclass, existing_move->client_vbss, m_database)) {
                // Trigger Channel Switch Succeeded
                return true;
            }
            LOG(ERROR) << "Move creation succeeded, but channel switch to channel " << channel
                       << " and op class " << opclass << " failed to send!";
            return false;
        }
        // Creation succeeded, send VBSS Destruction since Trigger Switch Announcement is not required.
        existing_move->state = eMoveProcessState::VBSS_DESTRUCTION;
        if (!vbss::vbss_actions::destroy_vbss(existing_move->client_vbss, false, m_database)) {
            LOG(ERROR) << "Move creation succeeded, but vbss destruction request to radio "
                       << src_ruid << " failed to send!";
            return false;
        }

        return true;
    }

    existing_move = get_matching_active_move(vbssid, eMoveProcessState::VBSS_DESTRUCTION);
    if (existing_move) {
        // Recieved destruction request response during a move

        if (!is_succeeded) {
            LOG(ERROR) << "VBSS Destruction on radio "
                       << existing_move->client_vbss.current_connected_ruid << " failed!";
        }
        active_moves.erase(vbssid);
        return true;
    }

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

    return true;
}

// If the Agent supports VBSS this message will include a VBSS Configuration Report TLV
bool vbss_task::handle_top_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto config_report_tlv = cmdu_rx.getClass<wfa_map::VbssConfigurationReport>();
    if (!config_report_tlv) {
        LOG(INFO) << "Agent with MAC " << src_mac
                  << " did not send a VBSS Configuration Report TLV with the "
                     "TOPOLOGY_RESPONSE_MESSAGE. It does not support VBSS.";
        return false;
    }

    LOG(INFO) << "VBSS Configuration Report received with data...";

    uint8_t num_radios = config_report_tlv->number_of_radios();
    for (uint8_t radio_idx = 0; radio_idx < num_radios; radio_idx++) {
        auto radio_tup = config_report_tlv->radio_list(radio_idx);
        if (!std::get<0>(radio_tup)) {
            LOG(ERROR) << "Failed to get radio (from VbssConfigurationReport) for index "
                       << radio_idx;
            continue;
        }
        auto radio_info = std::get<1>(radio_tup);

        sMacAddr ruid   = radio_info.radio_uid();
        uint8_t num_bss = radio_info.number_bss();
        LOG(INFO) << "RUID: " << ruid;

        for (uint8_t bss_idx = 0; bss_idx < num_bss; bss_idx++) {
            auto bss_tup = radio_info.bss_list(bss_idx);
            if (!std::get<0>(bss_tup)) {
                LOG(ERROR) << "Failed to get BSS (from VbssConfigurationReport) for radio at index "
                           << radio_idx << " at index " << bss_idx;
                continue;
            }
            auto bss_info = std::get<1>(bss_tup);

            sMacAddr bssid   = bss_info.bssid();
            std::string ssid = bss_info.ssid_str();

            LOG(DEBUG) << "    BSSID: " << bssid << ", SSID: \"" << ssid << "\"";
        }
    }

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

    return true;
}

bool vbss_task::handle_client_security_ctx_resp(const sMacAddr &src_mac,
                                                ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();

    if (!client_info_tlv) {
        LOG(ERROR) << "Client Security Context Response did not contain the Client Info TLV!";
        return false;
    }

    sMacAddr client_mac = client_info_tlv->client_mac();
    sMacAddr bssid      = client_info_tlv->bssid();

    auto client_sec_ctx_tlv = cmdu_rx.getClass<wfa_map::ClientSecurityContext>();

    if (!client_sec_ctx_tlv) {
        LOG(ERROR)
            << "Client Security Context Response did not contain the Client Security Context TLV!";
        return false;
    }

    // Created as shared pointer to a keep allocated ptk and gtk from being deallocated before they can be used
    bool is_connected = client_sec_ctx_tlv->client_connected_flags().client_connected;
    std::shared_ptr<vbss::sClientSecCtxInfo> sec_ctx_info =
        std::make_shared<vbss::sClientSecCtxInfo>(
            is_connected, client_sec_ctx_tlv->key_length(), client_sec_ctx_tlv->tx_packet_num(),
            client_sec_ctx_tlv->group_key_length(), client_sec_ctx_tlv->group_tx_packet_num());

    // Keep PTK and GTK in memory even when Client Security Context Info TLV is out of scope
    sec_ctx_info->ptk = new uint8_t[sec_ctx_info->key_length];
    sec_ctx_info->gtk = new uint8_t[sec_ctx_info->group_key_length];

    std::copy_n(client_sec_ctx_tlv->ptk(), sec_ctx_info->key_length, sec_ctx_info->ptk);
    std::copy_n(client_sec_ctx_tlv->gtk(), sec_ctx_info->group_key_length, sec_ctx_info->gtk);

    auto existing_move = get_matching_active_move(bssid, eMoveProcessState::CLIENT_SEC_CTX);
    if (existing_move) {
        // A move is in process for this mac address (and vbssid) and this state is the state that should be processed

        // Copy over security context info for later processing
        existing_move->sec_ctx_info = sec_ctx_info;

        vbss::sClientVBSS client_vbss = existing_move->client_vbss;

        auto agent = m_database.get_agent_by_radio_uid(client_vbss.current_connected_ruid);
        if (!agent) {
            LOG(ERROR) << "Could not continue move request for client with MAC address "
                       << client_mac << "! Could not find agent for radio uid "
                       << client_vbss.current_connected_ruid;
            return false;
        }

        sMacAddr agent_mac = agent->al_mac;

        existing_move->state = eMoveProcessState::VBSS_MOVE_PREP;

        // Next step is move preperation request. Execute and return since this data should not be sent to VBSS Manager
        if (!vbss::vbss_actions::send_move_prep_request(agent_mac, client_vbss, m_database)) {
            LOG(ERROR) << "Failed to send move preparation request for client with MAC address "
                       << client_mac << " to agent " << agent_mac;
            return false;
        }
        return true;
    }

    auto existing_creation = active_creation_events.get(bssid);

    if (existing_creation) {
        existing_creation->sec_ctx_info = sec_ctx_info;

        vbss::sClientVBSS client_vbss = existing_creation->client_vbss;

        if (!vbss::vbss_actions::create_vbss(client_vbss, existing_creation->dest_ruid,
                                             existing_creation->ssid, existing_creation->password,
                                             existing_creation->sec_ctx_info.get(), m_database)) {
            LOG(ERROR) << "Could not start VBSS creation from Client Security Context Response for "
                          "client with MAC address "
                       << client_mac << "! Create VBSS Request failed to send!";
            return false;
        }
        return true;
    }

    return true;
}

std::shared_ptr<vbss_task::sMoveEvent>
vbss_task::get_matching_active_move(const sMacAddr vbssid, const eMoveProcessState state)
{
    auto existing_move = active_moves.get(vbssid);
    if (existing_move == nullptr) {
        return nullptr;
    }
    // Existing move does not match given state
    if (existing_move->state != state) {
        return nullptr;
    }
    return existing_move;
}

bool vbss_task::should_trigger_channel_switch(const sMacAddr src_ruid, const sMacAddr dest_ruid,
                                              uint8_t &out_channel, uint8_t &out_opclass)
{

    uint8_t src_channel  = m_database.get_node_channel(tlvf::mac_to_string(src_ruid));
    uint8_t src_op_class = m_database.get_hostap_operating_class(src_ruid);

    uint8_t dest_channel  = m_database.get_node_channel(tlvf::mac_to_string(dest_ruid));
    uint8_t dest_op_class = m_database.get_hostap_operating_class(dest_ruid);

    if (src_channel == dest_channel && src_op_class == dest_op_class) {
        // Same channels and op classes, do not trigger channel switch
        return false;
    }

    out_channel = dest_channel;
    out_opclass = dest_op_class;
    return true;
}
