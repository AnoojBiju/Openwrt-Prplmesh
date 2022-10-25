#include "vbss_actions.h"

#include <tlvf/wfa_map/tlvClientCapabilityReport.h>
#include <tlvf/wfa_map/tlvClientInfo.h>
#include <tlvf/wfa_map/tlvTriggerChannelSwitchAnnouncement.h>
#include <tlvf/wfa_map/tlvVirtualBssCreation.h>
#include <tlvf/wfa_map/tlvVirtualBssDestruction.h>

namespace vbss {

bool vbss_actions::send_move_prep_request(const sMacAddr &agent_mac, const sClientVBSS &client_vbss,
                                          son::db &database)
{
    // NOTE: This type will likely change in the future
    return send_client_info_tlv_msg(
        ieee1905_1::eMessageType::VIRTUAL_BSS_MOVE_PREPARATION_REQUEST_MESSAGE, agent_mac,
        client_vbss, database);
}

bool vbss_actions::send_move_cancel_request(const sMacAddr &agent_mac,
                                            const sClientVBSS &client_vbss, son::db &database)
{
    // NOTE: This type will likely change in the future
    return send_client_info_tlv_msg(
        ieee1905_1::eMessageType::VIRTUAL_BSS_MOVE_CANCEL_REQUEST_MESSAGE, agent_mac, client_vbss,
        database);
}

bool vbss_actions::send_client_security_ctx_request(const sMacAddr &agent_mac,
                                                    const sClientVBSS &client_vbss,
                                                    son::db &database)
{
    // NOTE: This type will likely change in the future
    return send_client_info_tlv_msg(
        ieee1905_1::eMessageType::CLIENT_SECURITY_CONTEXT_REQUEST_MESSAGE, agent_mac, client_vbss,
        database);
}

bool vbss_actions::request_ap_radio_vbss_caps(const sMacAddr &agent_mac, son::db &database)
{
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];

    ieee1905_1::CmduMessageTx cmdu_msg_tx(tx_buffer, beerocks::message::MESSAGE_BUFFER_LENGTH);
    if (!cmdu_msg_tx.create(0,
                            ieee1905_1::eMessageType::VIRTUAL_BSS_CAPABILITIES_REQUEST_MESSAGE)) {
        LOG(ERROR) << "CMDU creation of type VIRTUAL_BSS_CAPABILITIES_REQUEST_MESSAGE has failed";
        return false;
    }

    if (!son_actions::send_cmdu_to_agent(agent_mac, cmdu_msg_tx, database)) {
        LOG(ERROR) << "Failed to send VBSS Capabilties request to agent (" << agent_mac << ")";
        return false;
    }
    return true;
}

bool vbss_actions::send_trigger_channel_switch_announcement(const sMacAddr &agent_mac,
                                                            const uint8_t csa_channel,
                                                            const uint8_t op_class,
                                                            const sClientVBSS &client_vbss,
                                                            son::db &database)
{
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));
    if (!cmdu_tx.create(
            0, ieee1905_1::eMessageType::TRIGGER_CHANNEL_SWITCH_ANNOUNCEMENT_REQUEST_MESSAGE)) {
        LOG(ERROR) << "Failed to create Trigger Channel Switch Announcement with type "
                      "CHANNEL_SELECTION_REQUEST_MESSAGE";
        return false;
    }

    auto client_info_tlv = cmdu_tx.addClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv) {
        LOG(ERROR)
            << "Failed to add Client Info TLV to Trigger Channel Switch Announcement request";
        return false;
    }

    client_info_tlv->bssid()      = client_vbss.vbssid;
    client_info_tlv->client_mac() = client_vbss.client_mac;

    auto trigger_chan_switch_tlv = cmdu_tx.addClass<wfa_map::TriggerChannelSwitchAnnouncement>();

    if (!trigger_chan_switch_tlv) {
        LOG(ERROR) << "Failed to add Trigger Channel Switch Announcement TLV to Trigger Channel "
                      "Switch Announcement request";
        return false;
    }

    trigger_chan_switch_tlv->opclass()     = op_class;
    trigger_chan_switch_tlv->csa_channel() = csa_channel;

    if (!son_actions::send_cmdu_to_agent(agent_mac, cmdu_tx, database)) {
        LOG(ERROR) << "Failed to send Trigger Channel Switch Announcement request to agent ("
                   << agent_mac << ")";
        return false;
    }
    return true;
}

bool vbss_actions::create_vbss(const sClientVBSS &client_vbss, const sMacAddr &dest_ruid,
                               const std::string &ssid, const std::string &password,
                               const sClientSecCtxInfo *client_sec_ctx, son::db &database)
{
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::VIRTUAL_BSS_REQUEST_MESSAGE)) {
        LOG(ERROR) << "Initializing VBSS Request Message for Create VBSS failed!";
        return false;
    }

    auto vbss_creation_req = cmdu_tx.addClass<wfa_map::VirtualBssCreation>();
    if (!vbss_creation_req) {
        LOG(ERROR) << "Adding tlvVirtualBSSCreation failed";
        return false;
    }

    auto client_capabilities_tlv_tx = cmdu_tx.addClass<wfa_map::tlvClientCapabilityReport>();
    if (!client_capabilities_tlv_tx) {
        LOG(ERROR) << "Creation of tlvClientCapabilityReport failed";
        return false;
    }

    auto agent = database.get_agent_by_radio_uid(dest_ruid);
    if (!agent) {
        LOG(ERROR) << "Failed to get agent for VBSSID " << client_vbss.vbssid;
        return false;
    }

    auto radio = agent->radios.get(dest_ruid);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio for VBSSID " << client_vbss.vbssid;
        return false;
    }

    vbss_creation_req->client_assoc() = client_vbss.client_is_associated;
    vbss_creation_req->client_mac()   = client_vbss.client_mac;
    vbss_creation_req->bssid()        = client_vbss.vbssid;
    vbss_creation_req->radio_uid()    = radio->radio_uid;

    vbss_creation_req->set_ssid(ssid);
    vbss_creation_req->set_pass(password);

    vbss_creation_req->set_dpp_connector(database.calculate_dpp_bootstrapping_str());

    if (client_vbss.client_is_associated) {
        if (!client_sec_ctx) {
            LOG(ERROR) << "Failed to send VBSS creation request! Client is associated but no "
                          "client security context is given!";
            return false;
        }

        auto sta_association_frame =
            database.get_association_frame_by_sta_mac(client_vbss.client_mac);
        if (!sta_association_frame) {
            LOG(ERROR) << "Failed to send VBSS creation request! Client is associated but no "
                          "client capatilities are given.";
            return false;
        }
        vbss_creation_req->set_ptk(client_sec_ctx->ptk, client_sec_ctx->key_length);
        vbss_creation_req->tx_packet_num() = client_sec_ctx->tx_packet_num;
        vbss_creation_req->set_gtk(client_sec_ctx->gtk, client_sec_ctx->group_key_length);
        vbss_creation_req->group_tx_packet_num() = client_sec_ctx->group_tx_packet_num;
        client_capabilities_tlv_tx->set_association_frame(sta_association_frame->buffer(),
                                                          sta_association_frame->len());
    }

    LOG(DEBUG) << "Sending VBSS creation request to Agent '" << agent->al_mac << "'." << std::endl
               << " Client associated: '" << client_vbss.client_is_associated << "'"
               << " Client MAC: '" << client_vbss.client_mac << "'"
               << " BSSID: '" << client_vbss.vbssid << "'"
               << " radio_uid: '" << radio->radio_uid << "'"
               << " SSID: '" << ssid << "'";

    if (!son_actions::send_cmdu_to_agent(agent->al_mac, cmdu_tx, database,
                                         tlvf::mac_to_string(radio->radio_uid))) {
        LOG(ERROR) << "Request to create VBSS failed to send to agent (" << agent->al_mac
                   << ") and radio (" << radio->radio_uid << ")";
        return false;
    }

    return true;
}

bool vbss_actions::destroy_vbss(const sClientVBSS &client_vbss, const bool should_disassociate,
                                son::db &database)
{
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::VIRTUAL_BSS_REQUEST_MESSAGE)) {
        LOG(ERROR) << "Initializing VBSS Request Message for Create VBSS failed!";
        return false;
    }

    auto vbss_destruct_req = cmdu_tx.addClass<wfa_map::VirtualBssDestruction>();
    if (!vbss_destruct_req) {
        LOG(ERROR) << "Adding tlvVirtualBSSDestruction failed";
        return false;
    }

    vbss_destruct_req->radio_uid()           = client_vbss.current_connected_ruid;
    vbss_destruct_req->bssid()               = client_vbss.vbssid;
    vbss_destruct_req->disassociate_client() = should_disassociate;

    auto agent = database.get_agent_by_radio_uid(client_vbss.current_connected_ruid);
    if (!agent) {
        LOG(ERROR) << "Failed to fetch agent for RUID \"" << client_vbss.current_connected_ruid
                   << "\"";
        return false;
    }
    if (son_actions::send_cmdu_to_agent(agent->al_mac, cmdu_tx, database,
                                        tlvf::mac_to_string(client_vbss.current_connected_ruid))) {
        LOG(ERROR) << "Request to destroy VBSS failed to send!";
        return false;
    }
    return true;
}

bool vbss_actions::send_client_info_tlv_msg(const ieee1905_1::eMessageType msg_type,
                                            const sMacAddr dest_agent_mac,
                                            const sClientVBSS &client_vbss, son::db &database)
{
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));
    if (!cmdu_tx.create(0, msg_type)) {
        LOG(ERROR) << "Creating Client Info Request of type "
                   << ieee1905_1::eMessageType_str(msg_type) << " failed";
        return false;
    }

    auto client_info_tlv = cmdu_tx.addClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv) {
        LOG(ERROR) << "Failed to add Client Info TLV for type "
                   << ieee1905_1::eMessageType_str(msg_type) << " failed";
        return false;
    }

    client_info_tlv->bssid()      = client_vbss.vbssid;
    client_info_tlv->client_mac() = client_vbss.client_mac;

    if (!son_actions::send_cmdu_to_agent(dest_agent_mac, cmdu_tx, database)) {
        LOG(ERROR) << "Request for type (" << ieee1905_1::eMessageType_str(msg_type)
                   << "), vbssid (" << client_vbss.vbssid << ") and agent MAC (" << dest_agent_mac
                   << ") failed to send";
        return false;
    }

    return true;
}

} // namespace vbss
