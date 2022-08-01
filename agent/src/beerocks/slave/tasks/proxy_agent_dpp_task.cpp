#include "proxy_agent_dpp_task.h"
#include "../son_slave_thread.h"
#include <tlvf/wfa_map/tlv1905EncapDpp.h>
#include <tlvf/wfa_map/tlvDppCceIndication.h>
#include <tlvf/wfa_map/tlvDppChirpValue.h>

namespace beerocks {

ProxyAgentDppTask::ProxyAgentDppTask(slave_thread &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::PROXY_AGENT_DPP), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool ProxyAgentDppTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                                    const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                                    std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::DPP_CCE_INDICATION_MESSAGE: {
        handle_dpp_cce_indication(cmdu_rx);
        return true;
    }
    case ieee1905_1::eMessageType::CHIRP_NOTIFICATION_MESSAGE: {
        handle_chirp_notification(cmdu_rx);
        return true;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
}

void ProxyAgentDppTask::handle_dpp_cce_indication(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto db = AgentDB::get();
    for (auto radio : db->get_radios_list()) {
        auto ap_manager_fd = m_btl_ctx.get_ap_manager_fd(radio->front.iface_name);
        if (!m_btl_ctx.forward_cmdu_to_uds(ap_manager_fd, cmdu_rx)) {
            LOG(ERROR) << "Failed to forward message to ap_manager";
            return;
        }
    }
}

void ProxyAgentDppTask::handle_chirp_notification(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // cmdu message received from ap_manager
    auto chirp_notification_tlv = cmdu_rx.getClass<wfa_map::tlvDppChirpValue>();
    if (!chirp_notification_tlv) {
        LOG(ERROR) << "Chirp notification message doesn't contain DPP chirp value tlv";
    }

    auto encap_1905_tlv = cmdu_rx.getClass<wfa_map::tlv1905EncapDpp>();

    if (!encap_1905_tlv) {
        LOG(ERROR) << "Direct encap dpp message doesn't contain 1905 encap Dpp tlv";
    }

    //check for authentication request frame.
    if (encap_1905_tlv->frame_type() == 0) {
        auth_db.auth_frame_buffer[current_auth_frame_idx] = (unsigned char *)malloc(
            encap_1905_tlv->encapsulated_frame_length() * sizeof(unsigned char));
        auth_db.auth_frame_buffer[current_auth_frame_idx] =
            encap_1905_tlv->encapsulated_frame(encap_1905_tlv->encapsulated_frame_length());
        auto chirp_value_tlv = cmdu_rx.getClass<wfa_map::tlvDppChirpValue>();
        if (!chirp_value_tlv) {
            LOG(ERROR) << "Direct encap dpp message doesn't contain chirp value tlv";
        }
        auth_db.chirp_value_hash[current_auth_frame_idx] =
            (unsigned char *)malloc(chirp_value_tlv->hash_length() * sizeof(unsigned char));
        auth_db.chirp_value_hash[current_auth_frame_idx] =
            chirp_value_tlv->hash(chirp_value_tlv->hash_length());
        current_auth_frame_idx++;
    }

    // authentication request message will be forwarded to ap_manager if compared hashes are same.
    if (auth_db.chirp_value_hash[current_auth_frame_idx--] == chirp_notification_tlv->hash()) {
        auto db = AgentDB::get();
        for (auto radio : db->get_radios_list()) {
            auto ap_manager_fd = m_btl_ctx.get_ap_manager_fd(radio->front.iface_name);
            if (!m_btl_ctx.forward_cmdu_to_uds(ap_manager_fd, cmdu_rx)) {
                LOG(ERROR) << "Failed to forward message to ap_manager";
                return;
            }
        }
    }

    // chirp notification message will be sent to the controller only if the hash comparison fails.
    m_btl_ctx.forward_cmdu_to_controller(cmdu_rx);
}

} // namespace beerocks
