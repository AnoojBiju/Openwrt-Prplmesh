/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "capability_reporting_task.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

#include <tlvf/wfa_map/tlvClientInfo.h>
#include <tlvf/wfa_map/tlvClientCapabilityReport.h>

namespace beerocks {

CapabilityReportingTask::CapabilityReportingTask(backhaul_manager &bhm_ctx,
                                                 ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CAPABILITY_REPORTING), m_bhm_ctx(bhm_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool CapabilityReportingTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                          const sMacAddr &src_mac,
                                          std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CLIENT_CAPABILITY_QUERY_MESSAGE: {
        (void) handle_client_capability_query(cmdu_rx, tlvf::mac_to_string(src_mac));
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

bool CapabilityReportingTask::handle_client_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                             const std::string &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received CLIENT_CAPABILITY_QUERY_MESSAGE , mid=" << std::dec << mid;

    auto client_info_tlv_r = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv_r) {
        LOG(ERROR) << "getClass wfa_map::tlvClientInfo failed";
        return false;
    }

    // send CLIENT_CAPABILITY_REPORT_MESSAGE back to the controller
    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::CLIENT_CAPABILITY_REPORT_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type CLIENT_CAPABILITY_REPORT_MESSAGE, has failed";
        return false;
    }

    auto client_info_tlv_t = m_cmdu_tx.addClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv_t) {
        LOG(ERROR) << "addClass wfa_map::tlvClientInfo has failed";
        return false;
    }
    client_info_tlv_t->bssid()      = client_info_tlv_r->bssid();
    client_info_tlv_t->client_mac() = client_info_tlv_r->client_mac();

    auto client_capability_report_tlv = m_cmdu_tx.addClass<wfa_map::tlvClientCapabilityReport>();
    if (!client_capability_report_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvClientCapabilityReport has failed";
        return false;
    }

    auto db = AgentDB::get();

    // Check if it is an error scenario - if the STA specified in the Client Capability Query
    // message is not associated with any of the BSS operated by the Multi-AP Agent [ though the
    // TLV does contain a BSSID, the specification says that we should answer if the client is
    // associated with any BSS on this agent.]
    auto radio = db->get_radio_by_mac(client_info_tlv_r->client_mac(), AgentDB::eMacType::CLIENT);
    if (!radio) {
        LOG(ERROR) << "radio for client mac " << client_info_tlv_r->client_mac() << " not found";

        // If it is an error scenario, set Success status to 0x01 = Failure and do nothing after it.
        client_capability_report_tlv->result_code() = wfa_map::tlvClientCapabilityReport::FAILURE;

        LOG(DEBUG) << "Result Code: FAILURE";
        LOG(DEBUG) << "STA specified in the Client Capability Query message is not associated with "
                      "any of the BSS operated by the Multi-AP Agent ";
        // Add an Error Code TLV
        auto error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvErrorCode>();
        if (!error_code_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvErrorCode has failed";
            return false;
        }
        error_code_tlv->reason_code() =
            wfa_map::tlvErrorCode::STA_NOT_ASSOCIATED_WITH_ANY_BSS_OPERATED_BY_THE_AGENT;
        error_code_tlv->sta_mac() = client_info_tlv_r->client_mac();
        return m_bhm_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, tlvf::mac_to_string(db->bridge.mac));
    }

    client_capability_report_tlv->result_code() = wfa_map::tlvClientCapabilityReport::SUCCESS;
    LOG(DEBUG) << "Result Code: SUCCESS";

    // Add frame body of the most recently received (Re)Association Request frame from this client.
    auto &client_info = radio->associated_clients.at(client_info_tlv_r->client_mac());
    client_capability_report_tlv->set_association_frame(client_info.association_frame.data(),
                                                        client_info.association_frame_length);

    LOG(DEBUG) << "Send a CLIENT_CAPABILITY_REPORT_MESSAGE back to controller";
    return m_bhm_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, tlvf::mac_to_string(db->bridge.mac));
}

} // namespace beerocks
