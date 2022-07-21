#include "vbss_task.h"
#include "../src/beerocks/master/son_actions.h"
#include <tlvf/wfa_map/tlvApRadioVbssCapabilities.h>
#include <tlvf/wfa_map/tlvClientInfo.h>
#include <tlvf/wfa_map/tlvClientSecurityContext.h>
#include <tlvf/wfa_map/tlvTriggerChannelSwitchAnnouncement.h>
#include <tlvf/wfa_map/tlvVbssConfigurationReport.h>
#include <tlvf/wfa_map/tlvVirtualBssEvent.h>

vbss_task::vbss_task(son::db &database_) : database(database_) {}

bool vbss_task::handle_ieee1905_1_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // Note: These are just temporararily used IEEE1905 message types. They will be changed in the future.
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::VIRTUAL_BSS_CAPABILITIES_REPONSE_MESSAGE:
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_RESULT_MESSAGE:
        // Virtual BSS Response
        return handle_vbss_event_response(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::CLIENT_CAPABILITY_REPORT_MESSAGE:
        // This type is definitely not right
        // Client Security Context Response
        return handle_client_security_ctx_resp(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE:
        // Trigger Channel Switch Announcement Response
        return handle_trigger_chan_switch_announce_resp(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_RESPONSE_MESSAGE:
        // This type is definitely not right
        // Virtual BSS Move Preperation Response
        return handle_move_response_msg(src_mac, cmdu_rx, false);
    case ieee1905_1::eMessageType::FAILED_CONNECTION_MESSAGE:
        // This type is definitely not right
        // Virtual BSS Move Cancel Response
        return handle_move_response_msg(src_mac, cmdu_rx, true);
    case ieee1905_1::eMessageType::TOPOLOGY_RESPONSE_MESSAGE:
        //VBSS Configuration Report TLV
        return handle_top_response_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_WSC_MESSAGE:
        //AP Radio VBSS Capabilities TLV
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_REQUEST_MESSAGE:
        //AP Radio VBSS Capabilities TLV
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    }
}
/*
 Virtual BSS Capabilities Response !!
    - AP Radio VBSS Capabilities TLV

 Virtual BSS Response !!
    - Virtual BSS Event TLV

 Client Security Context Response !!
    - Client Info TLV
    - Client Security Context TLV

 Trigger Channel Switch Announcement Response !!
    - Client Info TLV
    - Trigger Channel Switch Announcement TLV

 Virtual VBSS Move Preperation Response !!
    - Client Info TLV

 Virtual BSS Move Cancel Response !!
    - Client Info TLV

-----------------------------------------------

 1905 Topology Response Message !!
    - VBSS Configuration Report TLV
    - ...

 1905 AP-Autoconfiguration WSC message !!
    - AP Radio VBSS Capabilities TLV
    - ...

 BSS Configuration Request !!
    - AP Radio VBSS Capabilities TLV
    - ...
*/
// clang-format off
bool vbss_task::handle_ap_radio_vbss_caps_msg(const sMacAddr &src_mac,
                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto ap_vbss_caps_tlv = cmdu_rx.getClass<wfa_map::ApRadioVbssCapabilities>();
    if (!ap_vbss_caps_tlv) {
        // Message did not contain an AP Radio VBSS Capabilities TLV
        return false;
    }

    // A TLV is returned for each radio that supports VBSS, handle all of them
    beerocks::mac_map<vbss::sAPRadioVBSSCapabilities> ruid_caps_map;

    while (ap_vbss_caps_tlv) {
        vbss::sAPRadioVBSSCapabilities ap_radio_caps;

        ap_radio_caps.max_vbss        = ap_vbss_caps_tlv->max_vbss();
        ap_radio_caps.vbsses_subtract = ap_vbss_caps_tlv->vbss_settings().vbsss_subtract;
        ap_radio_caps.apply_fixed_bits_restrict = ap_vbss_caps_tlv->vbss_settings().vbssid_restrictions;
        ap_radio_caps.apply_vbssid_match_mask_restrict = ap_vbss_caps_tlv->vbss_settings().vbssid_match_and_mask_restrictions;
        ap_radio_caps.apply_fixed_bits_restrict = ap_vbss_caps_tlv->vbss_settings().fixed_bit_restrictions;
        ap_radio_caps.fixed_bits_mask  = ap_vbss_caps_tlv->fixed_bits_mask();
        ap_radio_caps.fixed_bits_value = ap_vbss_caps_tlv->fixed_bits_value();

        ruid_caps_map.add(ap_vbss_caps_tlv->radio_uid(), ap_radio_caps);

        ap_vbss_caps_tlv = cmdu_rx.getClass<wfa_map::ApRadioVbssCapabilities>();
    }

    //TODO: Send to VBSSManager (include src_mac = agent_mac)

    return true;
}
// clang-format on
bool vbss_task::handle_move_response_msg(const sMacAddr &src_mac,
                                         ieee1905_1::CmduMessageRx &cmdu_rx, bool did_cancel)
{

    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    std::string msg_desc = did_cancel ? "Move Cancel" : "Move Preparation";

    if (!client_info_tlv) {
        LOG(ERROR) << msg_desc << " Response did not contain a Client Info TLV!";
        return false;
    }

    sMacAddr client_mac = client_info_tlv->client_mac();
    sMacAddr bssid      = client_info_tlv->bssid();

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

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
    if (!client_info_tlv) {
        LOG(ERROR) << "Trigger Channel Switch Announcement Response did not contain the Trigger "
                      "Channel Switch Announcement TLV!";
        return false;
    }

    uint8_t csa_channel = channel_switch_tlv->csa_channel();
    uint8_t op_class    = channel_switch_tlv->opclass();

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

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
    sMacAddr ruid    = vbss_event_tlv->radio_uid();
    sMacAddr vbssid  = vbss_event_tlv->bssid();
    bool did_succeed = vbss_event_tlv->success();

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

    return true;
}

// If the Agent supports VBSS this message will include a VBSS Configuration Report TLV
bool handle_top_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto config_report_tlv = cmdu_rx.getClass<wfa_map::VbssConfigurationReport>();
    if (!config_report_tlv) {
        LOG(INFO) << "Agent with MAC " << tlvf::mac_to_string(src_mac)
                  << " does not support did not send a VBSS Configuration Report TLV with the "
                     "TOPOLOGY_RESPONSE_MESSAGE. It does not support VBSS.";
        return false;
    }

    uint8_t num_radios = config_report_tlv->number_of_radios();

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

    return true;
}

bool handle_client_security_ctx_resp(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
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

    bool client_is_connected     = client_sec_ctx_tlv->client_connected_flags().client_connected;
    uint8_t *ptk                 = client_sec_ctx_tlv->ptk();
    uint64_t tx_packet_num       = client_sec_ctx_tlv->tx_packet_num();
    uint8_t *gtk                 = client_sec_ctx_tlv->gtk();
    uint64_t group_tx_packet_num = client_sec_ctx_tlv->group_tx_packet_num();

    // TODO: Send to VBSS Manager (include src_mac = agent_mac)

    return true;
}
