#include "vbss_task.h"
#include "../src/beerocks/master/son_actions.h"
#include "dummy_tlvs/tlvAPRadioVBSSCapabilities.h"

vbss_task::vbss_task(son::db &database_) : database(database_) {}

bool vbss_task::handle_ieee1905_1_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // Note: These are just temporararily used IEEE1905 message types. They will be changed in the future.
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::AP_CAPABILITY_REPORT_MESSAGE:
        // Virtual BSS Capabilities Response
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_RESULT_MESSAGE:
        // Virtual BSS Response
        break;
    case ieee1905_1::eMessageType::CLIENT_CAPABILITY_REPORT_MESSAGE:
        // This type is definitely not right
        // Client Security Context Response
        break;
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE:
        // Trigger Channel Switch Announcement Response
        break;
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_RESPONSE_MESSAGE:
        // This type is definitely not right
        // Virtual BSS Move Preperation Response
        break;
    case ieee1905_1::eMessageType::FAILED_CONNECTION_MESSAGE:
        // This type is definitely not right
        // Virtual BSS Move Cancel Response
        break;
    case ieee1905_1::eMessageType::TOPOLOGY_RESPONSE_MESSAGE:
        //VBSS Configuration Report TLV
        break;
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_WSC_MESSAGE:
        //AP Radio VBSS Capabilities TLV
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_REQUEST_MESSAGE:
        //AP Radio VBSS Capabilities TLV
        return handle_ap_radio_vbss_caps_msg(src_mac, cmdu_rx);
    }
}
/*
 Virtual BSS Capabilities Response
    - AP Radio VBSS Capabilities TLV !!

 Virtual BSS Response
    - Virtual BSS Event TLV

 Client Security Context Response
    - Client Info TLV
    - Client Security Context TLV

 Trigger Channel Switch Announcement Response
    - Client Info TLV
    - Trigger Channel Switch Announcement TLV

 Virtual VBSS Move Preperation Response
    - Client Info TLV

 Virtual BSS Move Cancel Response
    - Client Info TLV

-----------------------------------------------

 1905 Topology Response Message
    - VBSS Configuration Report TLV
    - ...

 1905 AP-Autoconfiguration WSC message
    - AP Radio VBSS Capabilities TLV !!
    - ...

 BSS Configuration Request
    - AP Radio VBSS Capabilities TLV !!
    - ...
*/

bool vbss_task::handle_ap_radio_vbss_caps_msg(const sMacAddr &src_mac,
                                              ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto ap_vbss_caps_tlv = cmdu_rx.getClass<tlvAPRadioVBSSCapabilities>();
    if (!ap_vbss_caps_tlv) {
        // Message did not contain an AP Radio VBSS Capabilities TLV
        return false;
    }

    // A TLV is returned for each radio that supports VBSS, handle all of them
    beerocks::mac_map<vbss::sAPRadioVBSSCapabilities> ruid_caps_map;

    while (ap_vbss_caps_tlv) {
        vbss::sAPRadioVBSSCapabilities ap_radio_caps;

        ap_radio_caps.max_vbss        = ap_vbss_caps_tlv->max_vbss();
        ap_radio_caps.vbsses_subtract = ap_vbss_caps_tlv->vbss_settings().vbsss_subtract();
        ap_radio_caps.apply_fixed_bits_restrict =
            ap_vbss_caps_tlv->vbss_settings().vbssid_restrictions();
        ap_radio_caps.apply_vbssid_match_mask_restrict =
            ap_vbss_caps_tlv->vbss_settings().vbssid_match_and_mask_restrictions();
        ap_radio_caps.apply_fixed_bits_restrict =
            ap_vbss_caps_tlv->vbss_settings().fixed_bit_restrictions();
        ap_radio_caps.fixed_bits_mask  = ap_vbss_caps_tlv->fixed_bits_mask();
        ap_radio_caps.fixed_bits_value = ap_vbss_caps_tlv->fixed_bits_value();

        ruid_caps_map.insert({ap_vbss_caps_tlv->radio_uid(), ap_radio_caps});

        ap_vbss_caps_tlv = cmdu_rx.getClass<tlvAPRadioVBSSCapabilities>();
    }

    //TODO: Send to VBSSManager

    return true;
}
