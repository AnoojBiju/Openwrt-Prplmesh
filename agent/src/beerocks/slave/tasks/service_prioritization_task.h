/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _SERVICE_PRIORITIZATION_TASK_H_
#define _SERVICE_PRIORITIZATION_TASK_H_

#include "task.h"

#include <bpl/bpl.h>
#include <bpl/bpl_service_prio_utils.h>
#include <tlvf/CmduMessageTx.h>

namespace beerocks {

// Forward declaration for BackhaulManager context saving
class slave_thread;

class ServicePrioritizationTask : public Task {
public:
    ServicePrioritizationTask(slave_thread &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;
    bool clear_configuration() { return qos_flush_setup(); };

private:
    void handle_service_prioritization_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                               const sMacAddr &src_mac);
    void handle_slave_channel_selection_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                 const sMacAddr &src_mac);

    /**
    * @brief Sends notification to HostAP/Driver about the current service prioritization config
    *
    * @return true if config applied or handled properly, otherwise false.
    * */
    bool send_service_prio_config(const beerocks_message::sServicePrioConfig &request);

    void gather_iface_details(std::list<bpl::ServicePrioritizationUtils::sInterfaceTagInfo> *);

    bool qos_apply_active_rule();
    bool qos_flush_setup();
    bool qos_setup_single_value_map(uint8_t pcp);
    bool qos_setup_dscp_map();
    bool qos_setup_up_map();

    slave_thread &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    std::shared_ptr<beerocks::bpl::ServicePrioritizationUtils> service_prio_utils;

    enum : uint8_t { QOS_USE_DSCP_MAP = 0x08, QOS_USE_UP = 0x09 };
};

} // namespace beerocks

#endif // _SERVICE_PRIORITIZATION_TASK_H_
