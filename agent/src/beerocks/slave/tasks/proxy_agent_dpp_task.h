#ifndef _PROXY_AGENT_DPP_TASK_H_
#define _PROXY_AGENT_DPP_TASK_H_

#include "task.h"
#include <bcl/network/sockets_impl.h>
#include <tlvf/CmduMessageTx.h>

namespace beerocks {

// Forward declaration for Agent context saving
class slave_thread;

class ProxyAgentDppTask : public Task {
public:
    ProxyAgentDppTask(slave_thread &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~ProxyAgentDppTask() {}

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    slave_thread &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    int active_onboarding_ap_manager_fd = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * @brief Parse DPP CCE Indication message.
     *
     * @param cmdu_rx Received CMDU.
     * @return true on success, otherwise false.
     */
    void handle_dpp_cce_indication(ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Parse Chirp Notification Message.
     *
     * @param cmdu_rx Received CMDU.
     * @return true on success, otherwise false.
     */
    void handle_chirp_notification(ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Parse Proxied Encap DPP Message.
     *
     * @param cmdu_rx Received CMDU.
     * @return true on success, otherwise false.
     */
    void handle_proxied_encap_dpp(int fd, const sMacAddr &src_mac,
                                  ieee1905_1::CmduMessageRx &cmdu_rx);
};
} // namespace beerocks

#endif // _PROXY_AGENT_DPP_TASK_H_
