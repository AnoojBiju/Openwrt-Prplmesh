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
#include "../cac_capabilities_database.h"
#include "task.h"
#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvChannelScanCapabilities.h>

namespace beerocks {

// Forward declaration for agent context saving
class slave_thread;

class CapabilityReportingTask : public Task {
public:
    CapabilityReportingTask(slave_thread &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    slave_thread &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    beerocks::CacCapabilitiesDatabase m_cac_capabilities;

    void handle_client_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                        const sMacAddr &src_mac);
    void handle_ap_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);

    void handle_backhaul_sta_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                              const sMacAddr &src_mac);

    /**
     * @brief Adds an AP HT Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if radio on given interface supports HT capabilities.
     * See section 17.2.8 of Multi-AP Specification for details.
     *
     * @param iface_name Interface on which radio operates.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_ht_capabilities(const std::string &iface_name);

    /**
     * @brief Adds an AP VHT Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if radio on given interface supports VHT capabilities.
     * See section 17.2.9 of Multi-AP Specification for details.
     *
     * @param iface_name Interface on which radio operates.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_vht_capabilities(const std::string &iface_name);

    /**
     * @brief Adds an AP HE Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if radio on given interface supports HE capabilities.
     * See section 17.2.10 of Multi-AP Specification for details.
     *
     * @param iface_name Interface on which radio operates.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_he_capabilities(const std::string &iface_name);

    /**
     * @brief Adds an AP WIFI6 Capabilities TLV to AP Capability Report message.
     *
     * TLV is added to message only if radio on given interface supports HE capabilities.
     * See section 17.2.72 of Multi-AP Specification for details.
     *
     * @param iface_name Interface on which radio operates.
     *
     * @return True on success and false otherwise.
     */
    bool add_ap_wifi6_capabilities(const std::string &iface_name);

    /**
     * @brief Adds Channel Scan Capabilities TLV to AP Capability Report message.
     *
     * The TLV is already created by the caller. This function adds
     * information to the given tlv based on radio on given interface.
     * See section 17.2.38 of Multi-AP Specification v2 for details.
     *
     * @param radio Pointer to the AgentDB's radio element.
     *
     * @param channel_scan_capabilities_tlv Channel Scan Capabilities TLV.
     *
     * @return True on success and false otherwise.
     */
    bool add_channel_scan_capabilities(
        const AgentDB::sRadio *radio,
        wfa_map::tlvChannelScanCapabilities &channel_scan_capabilities_tlv);

    /**
     * @brief Adds CAC-Capabilities TLV to AP Capability Report message.
     * 
     * @return true on success, otherwise false.
     */
    bool add_cac_capabilities_tlv();

    /**
     * @brief Adds Device Inventory TLVF to AP Capability Report message.
     * 
     * @return true on success, otherwise false.
     */
    bool add_device_inventory_tlv();

public:
    /* Note:
     * Profile-2 AP Capability TLV is being added by to the AutoConfiguration Message with M1, and
     * here too on the AP CAPABILITY REPORT message.
     * Therefore, set this tlv add function as public, so when the the task will run on the Unified
     * Agent context, the AutoConfiguration could use it.
     * 

    /**
     * @brief Add Profile-2 AP Capability to given CMDU. 
     * 
     * @param cmdu_tx CMDU object to add the Profile-2 AP capabilities to.
     * @return true on success, otherwise false.
     */
    bool add_profile2_ap_capability_tlv(ieee1905_1::CmduMessageTx &cmdu_tx);

private:
};

} // namespace beerocks

#endif // _CAPABILITY_REPORTING_TASK_H_
