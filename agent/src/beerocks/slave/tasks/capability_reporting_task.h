/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CAPABILITY_REPORTING_TASK_H_
#define _CAPABILITY_REPORTING_TASK_H_

#include "../agent_db.h"
#include "task.h"

#include <tlvf/CmduMessageTx.h>

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class CapabilityReportingTask : public Task {
public:
    CapabilityReportingTask(backhaul_manager &bhm_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    backhaul_manager &m_bhm_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    void handle_client_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                        const std::string &src_mac);
    void handle_ap_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx, const std::string &src_mac);

    /**
     * @brief Adds an AP HT Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if given radio supports HT capabilities.
     * See section 17.2.8 of Multi-AP Specification for details.
     *
     * @param radio Radio structure containing the information required to fill in the TLV.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_ht_capabilities(const AgentDB::sRadio &radio);

    /**
     * @brief Adds an AP VHT Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if given radio supports VHT capabilities.
     * See section 17.2.9 of Multi-AP Specification for details.
     *
     * @param radio Radio structure containing the information required to fill in the TLV.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_vht_capabilities(const AgentDB::sRadio &radio);

    /**
     * @brief Adds an AP HE Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if given radio supports HE capabilities.
     * See section 17.2.10 of Multi-AP Specification for details.
     *
     * @param radio Radio structure containing the information required to fill in the TLV.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_he_capabilities(const AgentDB::sRadio &radio);
};

} // namespace beerocks

#endif // _CAPABILITY_REPORTING_TASK_H_
