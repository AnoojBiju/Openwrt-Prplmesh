#include "vbss_task.h"
#include "../son_slave_thread.h"
#include <tlvf/ieee_1905_1/tlvAlMacAddress.h>
#include <tlvf/wfa_map/tlvApRadioVbssCapabilities.h>
#include <tlvf/wfa_map/tlvClientInfo.h>
#include <tlvf/wfa_map/tlvVirtualBssCreation.h>
#include <tlvf/wfa_map/tlvVirtualBssDestruction.h>
#include <tlvf/wfa_map/tlvVirtualBssEvent.h>

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
    case ieee1905_1::eMessageType::VIRTUAL_BSS_MOVE_PREPARATION_REQUEST_MESSAGE: {
        handle_virtual_bss_move_preparation_request(cmdu_rx);
        return true;
    }
    case ieee1905_1::eMessageType::VIRTUAL_BSS_RESPONSE_MESSAGE: {
        handle_virtual_bss_response(cmdu_rx);
        return true;
    }
    case ieee1905_1::eMessageType::VIRTUAL_BSS_CAPABILITIES_REQUEST_MESSAGE: {
        handle_virtual_bss_cap_request(cmdu_rx);
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
        if (vbss_creation_tlv->client_assoc()) {
            m_move_requests[vbss_creation_tlv->bssid()] = vbss_creation_tlv->client_mac();
        } else {
            m_move_requests[vbss_creation_tlv->bssid()] = net::network_utils::ZERO_MAC;
        }
        //LOG(DEBUG) << "Added: " << vbss_creation_tlv->bssid()
        //           << " with station: " << m_move_requests[vbss_creation_tlv->bssid()] << std::endl;
    } else {
        auto vbss_destruction_tlv = cmdu_rx.getClass<wfa_map::VirtualBssDestruction>();
        if (vbss_destruction_tlv) {
            radio_uid = vbss_destruction_tlv->radio_uid();
            m_delete_events.push_back(vbss_destruction_tlv->bssid());
            //LOG(DEBUG) << "Added destruction to vector m_delete events" << std::endl;
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

bool VbssTask::handle_security_context_request(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv) {
        LOG(ERROR) << "Security Context Request didn't contain client cap tlv";
        return false;
    }

    // DB is a singleton with locks. Need to perform Get First
    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(client_info_tlv->bssid(), AgentDB::eMacType::BSSID);
    if (!radio) {
        LOG(ERROR) << "Could not find radio with BSSID " << client_info_tlv->bssid();
        return false;
    }
    auto ap_manager_fd = m_btl_ctx.get_ap_manager_fd(radio->front.iface_name);
    if (!m_btl_ctx.forward_cmdu_to_uds(ap_manager_fd, cmdu_rx)) {
        LOG(ERROR) << "Failed to forward message to AP manager";
        return false;
    }
    return true;
}

bool VbssTask::handle_virtual_bss_move_preparation_request(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv) {
        LOG(ERROR) << "Virtual BSS Move Preparation Request did not contain client capability tlv!";
        return false;
    }

    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(client_info_tlv->bssid(), AgentDB::eMacType::BSSID);
    if (!radio) {
        LOG(ERROR) << "Could not find the radio with BSSID " << client_info_tlv->bssid();
        return false;
    }
    auto ap_manager_fd = m_btl_ctx.get_ap_manager_fd(radio->front.iface_name);
    if (!m_btl_ctx.forward_cmdu_to_uds(ap_manager_fd, cmdu_rx)) {
        LOG(ERROR) << "Failed to forward message to AP manager";
        return false;
    }
    return true;
}

void VbssTask::handle_virtual_bss_response(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    LOG(DEBUG) << "Received Virtual BSS Response with MID=" << cmdu_rx.getMessageId() << std::endl;
    auto virtual_bss_event_tlv = cmdu_rx.getClass<wfa_map::VirtualBssEvent>();
    if (!virtual_bss_event_tlv) {
        LOG(ERROR) << "Virtual BSS Response does not contain Virtual BSS Event TLV!";
        return;
    }

    // CMDU received from ap_manager
    m_btl_ctx.forward_cmdu_to_controller(cmdu_rx);
    // Whether this is a creation or deletion it needs to be forwarded to monitor to
    // register and unregister from the events

    if (virtual_bss_event_tlv->success()) {

        // If the request was handled successfully, we have to send a
        // topology notification as a BSS has either be created or
        // removed as a result.
        // Send to MON so it can register events and monitor stations on vbss
        // When we receive a response check to see if successful for a known creation request
        // if successful we will create a new dumbed down request message to send to monitor
        // thread
        if (m_move_requests.end() != m_move_requests.find(virtual_bss_event_tlv->bssid())) {
            // known creation with possible move
            auto sta_mac = m_move_requests[virtual_bss_event_tlv->bssid()];
            m_move_requests.erase(virtual_bss_event_tlv->bssid());
            auto cmdu_header =
                m_cmdu_tx.create(0, ieee1905_1::eMessageType::VIRTUAL_BSS_REQUEST_MESSAGE);
            if (!cmdu_header) {
                LOG(ERROR) << "FAILED to create vbss request to send to monitor thread";
                return;
            }
            LOG(INFO) << "Sending request to monitor thread to register for events for bssid: "
                      << virtual_bss_event_tlv->bssid()
                      << " with MID= " << m_cmdu_tx.getMessageId();
            auto vbss_creation_req = m_cmdu_tx.addClass<wfa_map::VirtualBssCreation>();
            if (!vbss_creation_req) {
                LOG(ERROR) << "Failed to vbss creation request to send to monitor";
                m_move_requests.erase(virtual_bss_event_tlv->bssid());
                return;
            }
            // Yes, this isn't fully filled in
            // Monitor doesn't need any more information then this
            vbss_creation_req->bssid()      = virtual_bss_event_tlv->bssid();
            vbss_creation_req->client_mac() = sta_mac;
            auto db                         = AgentDB::get();
            auto radio =
                db->get_radio_by_mac(virtual_bss_event_tlv->radio_uid(), AgentDB::eMacType::RADIO);
            if (!radio) {
                LOG(ERROR) << "Failed to get radio for vbss id: " << virtual_bss_event_tlv->bssid();
            } else {
                auto monitor_fd = m_btl_ctx.get_monitor_fd(radio->front.iface_name);
                if (!m_btl_ctx.send_cmdu(monitor_fd, m_cmdu_tx)) {
                    LOG(ERROR)
                        << "Failed to forward to monitor thread virtual bss response message";
                }
            }
            return;
        }
        auto iter = std::find(m_delete_events.begin(), m_delete_events.end(),
                              virtual_bss_event_tlv->bssid());
        if (iter != m_delete_events.end()) {
            // Response from a delete event, need to tell monitor
            m_delete_events.erase(iter);
            LOG(INFO) << "Sending delete event to monitor for vbss "
                      << virtual_bss_event_tlv->bssid();
            auto cmdu_header =
                m_cmdu_tx.create(0, ieee1905_1::eMessageType::VIRTUAL_BSS_REQUEST_MESSAGE);
            if (!cmdu_header) {
                LOG(ERROR) << "Failed to make cmdu header for request to destroy to monitor";
                return;
            }
            auto vbss_deletion = m_cmdu_tx.addClass<wfa_map::VirtualBssDestruction>();
            if (!vbss_deletion) {
                LOG(ERROR) << "Failed to make vbss destruction tlv";
                return;
            }
            vbss_deletion->bssid() = virtual_bss_event_tlv->bssid();
            auto db                = AgentDB::get();
            auto radio =
                db->get_radio_by_mac(virtual_bss_event_tlv->radio_uid(), AgentDB::eMacType::RADIO);
            if (!radio) {
                LOG(ERROR) << "Failed to get radio for vbss id: " << virtual_bss_event_tlv->bssid();
            } else {
                if (!m_btl_ctx.send_cmdu(m_btl_ctx.get_monitor_fd(radio->front.iface_name),
                                         m_cmdu_tx)) {
                    LOG(ERROR)
                        << "Failed to forward to monitor thread the vbss destruction message";
                }
            }
        }
        return;
    }
}

void VbssTask::handle_virtual_bss_cap_request(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    LOG(DEBUG) << "Received virtual BSS Cap request";
    // This RX Is blank, no need to parse
    auto cmdu_header =
        m_cmdu_tx.create(0, ieee1905_1::eMessageType::VIRTUAL_BSS_CAPABILITIES_REPONSE_MESSAGE);
    if (!cmdu_header) {
        LOG(ERROR) << "Failed to create VBSS Cap Response Message";
        return;
    }
    sMacAddr zeroMac = {};
    auto db          = AgentDB::get();
    auto radList     = db->get_radios_list();
    for (auto radio : radList) {
        LOG(DEBUG) << "Creating Ap Cap message for radio: " << radio->front.iface_mac;
        auto tlvVbssCap = m_cmdu_tx.addClass<wfa_map::ApRadioVbssCapabilities>();
        if (!tlvVbssCap) {
            LOG(ERROR) << "Failed to add ap radio vbss capabilities to cmdu tx";
            // DO we have to do a clean up?
            return;
        }
        // The information we need from this will nl80211 is stored NL80211_ATTR_INTERFACE_COMBINATIONS
        // IW Code info.c line 543 has the reference
        // For now hard coding
        // Will need to implement this information NL80211_ATTR_INTERFACE_COMBINATIONS
        sMacAddr mask = radio->front.iface_mac;
        // Dirty trick; zero out last 4 bytes of address to make sure we can create the required number of
        // orthogonal
        mask.oct[2] = 0;
        mask.oct[3] = 0;
        mask.oct[4] = 0;
        mask.oct[5] = 0;

        tlvVbssCap->radio_uid()                                        = radio->front.iface_mac;
        tlvVbssCap->max_vbss()                                         = beerocks::IFACE_TOTAL_VAPS;
        tlvVbssCap->vbss_settings().vbsss_subtract                     = true;
        tlvVbssCap->vbss_settings().vbssid_restrictions                = true;
        tlvVbssCap->vbss_settings().vbssid_match_and_mask_restrictions = true;
        tlvVbssCap->vbss_settings().fixed_bit_restrictions             = false;
        tlvVbssCap->fixed_bits_mask()                                  = mask;
        tlvVbssCap->fixed_bits_value()                                 = zeroMac;
    }
    if (!m_btl_ctx.send_cmdu_to_controller({}, m_cmdu_tx)) {
        LOG(ERROR) << "Failed to send ap auto bss capability response message";
        return;
    }
    return;
}

} // namespace beerocks
