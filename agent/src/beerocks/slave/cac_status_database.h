/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CAC_STATUS_DATABASE_H_
#define _CAC_STATUS_DATABASE_H_

#include "cac_status_interface.h"

namespace beerocks {

class CacStatusDatabase : public CacStatusInterface {
public:
    CacAvailableChannels get_available_channels(const sMacAddr &radio_mac) const override;
    bool update_cac_status_db(const AgentDB::sRadio *radio) override;

    /**
     * @brief Fills in CAC Status Report TLV by given radio.
     * 
     * @param radio Pointer to the AgentDB's radio element.
     * @param cac_status_report_tlv CAC Status Report TLV.
     * @return True on success, false otherwise.
     */
    bool add_cac_status_report_tlv(
        const AgentDB::sRadio *radio,
        const std::shared_ptr<wfa_map::tlvProfile2CacStatusReport> cac_status_report_tlv);

    sCacCompletionStatus get_completion_status(const AgentDB::sRadio *radio) const override;

    /**
     * @brief Fills in CAC Completion Report TLV by given radio.
     * 
     * @param radio Pointer to the AgentDB's radio element.
     * @param cac_completion_report_tlv CAC Completion Report TLV.
     * @return True on success, false otherwise.
     */
    bool add_cac_completion_report_tlv(
        const AgentDB::sRadio *radio,
        const std::shared_ptr<wfa_map::tlvProfile2CacCompletionReport> cac_completion_report_tlv);

private:
    std::unordered_map<sMacAddr, CacAvailableChannels> m_available_channels;
};

// utilities based on CacCapabilities interface

} // namespace beerocks

#endif
