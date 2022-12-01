#include "vbss_task.h"
#include "../son_slave_thread.h"
#include <tlvf/wfa_map/tlvVirtualBssCreation.h>
#include <tlvf/wfa_map/tlvVirtualBssDestruction.h>
#include <tlvf/wfa_map/tlvClientInfo.h>

namespace beerocks {

VbssTask::VbssTask(slave_thread &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::VBSS), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool VbssTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                           const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                           std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::VIRTUAL_BSS_REQUEST_MESSAGE: {
        handle_virtual_bss_request(cmdu_rx);
        return true;
    }
    case ieee1905_1::eMessageType::CLIENT_SECURITY_CONTEXT_REQUEST_MESSAGE: {
        handle_security_context_request(cmdu_rx);
        return true;
    }
    case ieee1905_1::eMessageType::VIRTUAL_BSS_RESPONSE_MESSAGE: {
        handle_virtual_bss_response(cmdu_rx);
        return true;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
}

void VbssTask::handle_virtual_bss_request(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    sMacAddr radio_uid = net::network_utils::ZERO_MAC;

    // The request might be a creation or destruction request, look
    // for a radio_uid in both.
    auto vbss_creation_tlv = cmdu_rx.getClass<wfa_map::VirtualBssCreation>();
    if (vbss_creation_tlv) {
        radio_uid = vbss_creation_tlv->radio_uid();
    } else {
        auto vbss_destruction_tlv = cmdu_rx.getClass<wfa_map::VirtualBssDestruction>();
        if (vbss_destruction_tlv) {
            radio_uid = vbss_destruction_tlv->radio_uid();
        }
    }

    if (radio_uid == net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "No radio UID found in Virtual BSS Request!";
        return;
    }

    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(radio_uid, AgentDB::eMacType::RADIO);
    if (!radio) {
        LOG(ERROR) << "Could not find radio with RUID '" << radio_uid << "'!";
        return;
    }
    auto ap_manager_fd = m_btl_ctx.get_ap_manager_fd(radio->front.iface_name);
    if (!m_btl_ctx.forward_cmdu_to_uds(ap_manager_fd, cmdu_rx)) {
        LOG(ERROR) << "Failed to forward message to ap_manager!";
        return;
    }
}

void VbssTask::handle_virtual_bss_response(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    LOG(DEBUG) << "Received Virtual BSS Response";
    // CMDU received from ap_manager
    m_btl_ctx.forward_cmdu_to_controller(cmdu_rx);
}

bool VbssTask::handle_security_context_request(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    if(!client_info_tlv){
        LOG(ERROR) << "Security Context Request didn't contain client cap tlv";
        return false;
    }

    // DB is a singleton with locks. Need to perform Get First
    auto db = AgentDB::get();
    auto radio = db->get_radio_by_mac(client_info_tlv->bssid(), AgentDB::eMacType::BSSID);
    if(!radio){
        LOG(ERROR) << "Could not find radio with BSSID " << client_info_tlv->bssid();
        return false;
    }
    auto ap_manager_fd = m_btl_ctx.get_ap_manager_fd(radio->front.iface_name);
    if(!m_btl_ctx.forward_cmdu_to_uds(ap_manager_fd, cmdu_rx)){
        LOG(ERROR) << "Failed to forward message to AP manager";
        return false;
    }
    return true;
}

bool VbssTask::handle_security_context_response(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    LOG(DEBUG) << "Forwarding security context response to controller";
    // CMDU received from ap_manager
    return m_btl_ctx.forward_cmdu_to_controller(cmdu_rx);
}

} // namespace beerocks
