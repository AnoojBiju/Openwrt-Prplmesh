#include "vbss_task.h"
#include "../src/beerocks/master/son_actions.h"

vbss_task::vbss_task(son::db &database_) : database(database_) {}

bool vbss_task::handle_ieee1905_1_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // Note: These are just temporararily used IEEE1905 message types. They will be changed in the future.
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::AP_CAPABILITY_REPORT_MESSAGE:
        // Virtual BSS Capabilities Response
        break;
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
        break;
    case ieee1905_1::eMessageType::BSS_CONFIGURATION_REQUEST_MESSAGE:
        //AP Radio VBSS Capabilities TLV
        break;
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

 Virtual VBSS Move Preperation Response
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
