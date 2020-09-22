/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "capability_reporting_task.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

#include <tlvf/wfa_map/tlvApCapability.h>
#include <tlvf/wfa_map/tlvApHeCapabilities.h>
#include <tlvf/wfa_map/tlvApHtCapabilities.h>
#include <tlvf/wfa_map/tlvApVhtCapabilities.h>
#include <tlvf/wfa_map/tlvChannelScanCapabilities.h>
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
    case ieee1905_1::eMessageType::AP_CAPABILITY_QUERY_MESSAGE: {
        (void) handle_ap_capability_query(cmdu_rx, tlvf::mac_to_string(src_mac));
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

bool CapabilityReportingTask::handle_ap_capability_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const std::string &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received AP_CAPABILITY_QUERY_MESSAGE, mid=" << std::dec << mid;

    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::AP_CAPABILITY_REPORT_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type AP_CAPABILITY_REPORT_MESSAGE, has failed";
        return false;
    }

    auto ap_capability_tlv = m_cmdu_tx.addClass<wfa_map::tlvApCapability>();
    if (!ap_capability_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvApCapability has failed";
        return false;
    }

    auto db = AgentDB::get();

    // Capability bitmask is set to 0 because neither unassociated STA link metrics
    // reporting or agent-initiated RCPI-based steering are supported

    for (const auto &slave : m_bhm_ctx.slaves_sockets) {
        // TODO skip slaves that are not operational
        auto radio_mac = slave->radio_mac;

        auto radio = db->get_radio_by_mac(radio_mac);
        if (!radio) {
            LOG(ERROR) << "radio with mac " << radio_mac << " does not exist in the db";
            continue;
        }

        if (!tlvf_utils::add_ap_radio_basic_capabilities(m_cmdu_tx, radio_mac,
                                                         radio->front.preferred_channels)) {
            return false;
        }

        if (!add_ap_ht_capabilities(*radio)) {
            return false;
        }

        if (!add_ap_vht_capabilities(*radio)) {
            return false;
        }

        if (!add_ap_he_capabilities(*radio)) {
            return false;
        }
    }

    // Add channel scan capabilities
    auto channel_scan_capabilities_tlv = m_cmdu_tx.addClass<wfa_map::tlvChannelScanCapabilities>();
    if (!channel_scan_capabilities_tlv) {
        LOG(ERROR) << "Error creating TLV_CHANNEL_SCAN_CAPABILITIES";
        return false;
    }

    // Add Channel Scan Capabilities
    for (const auto &slave : m_bhm_ctx.slaves_sockets) {
        auto radio_channel_scan_capabilities = channel_scan_capabilities_tlv->create_radio_list();
        if (!radio_channel_scan_capabilities) {
            LOG(ERROR) << "create_radio_list() has failed!";
            return false;
        }
        radio_channel_scan_capabilities->radio_uid()                 = slave->radio_mac;
        radio_channel_scan_capabilities->capabilities().on_boot_only = 1;
        radio_channel_scan_capabilities->capabilities().scan_impact =
            0x2; // Time slicing impairment (Radio may go off channel for a series of short intervals)
                 // Create operating class object
        auto op_class_channels = radio_channel_scan_capabilities->create_operating_classes_list();
        if (!op_class_channels) {
            LOG(ERROR) << "create_operating_classes_list() has failed!";
            return false;
        }

        // Push operating class object to the list of operating class objects
        if (!channel_scan_capabilities_tlv->add_radio_list(radio_channel_scan_capabilities)) {
            LOG(ERROR) << "add_radio_list() has failed!";
            return false;
        }
    }

    LOG(DEBUG) << "Sending AP_CAPABILITY_REPORT_MESSAGE , mid: " << std::hex << mid;
    return m_bhm_ctx.send_cmdu_to_broker(m_cmdu_tx, src_mac, tlvf::mac_to_string(db->bridge.mac));
}

bool CapabilityReportingTask::add_ap_ht_capabilities(const AgentDB::sRadio &radio)
{
    if (!radio.ht_supported) {
        return true;
    }

    auto tlv = m_cmdu_tx.addClass<wfa_map::tlvApHtCapabilities>();
    if (!tlv) {
        LOG(ERROR) << "Error creating TLV_AP_HT_CAPABILITIES";
        return false;
    }

    tlv->radio_uid() = radio.front.iface_mac;

    /**
     * See iw/util.c for details on how to compute fields.
     * Code has been preserved as close as possible to that in the iw command line tool.
     */
    bool tx_mcs_set_defined = !!(radio.ht_mcs_set[12] & (1 << 0));
    if (tx_mcs_set_defined) {
        tlv->flags().max_num_of_supported_tx_spatial_streams = (radio.ht_mcs_set[12] >> 2) & 3;
        tlv->flags().max_num_of_supported_rx_spatial_streams = 0; // TODO: Compute value (#1163)
    }
    tlv->flags().short_gi_support_20mhz = radio.ht_capability & BIT(5);
    tlv->flags().short_gi_support_40mhz = radio.ht_capability & BIT(6);
    tlv->flags().ht_support_40mhz       = radio.ht_capability & BIT(1);

    return true;
}

bool CapabilityReportingTask::add_ap_vht_capabilities(const AgentDB::sRadio &radio)
{
    if (!radio.vht_supported) {
        return true;
    }

    auto tlv = m_cmdu_tx.addClass<wfa_map::tlvApVhtCapabilities>();
    if (!tlv) {
        LOG(ERROR) << "Error creating TLV_AP_VHT_CAPABILITIES";
        return false;
    }

    tlv->radio_uid() = radio.front.iface_mac;

    /**
     * See iw/util.c for details on how to compute fields
     * Code has been preserved as close as possible to that in the iw command line tool.
     */
    tlv->supported_vht_tx_mcs() = radio.vht_mcs_set[4] | (radio.vht_mcs_set[5] << 8);
    tlv->supported_vht_rx_mcs() = radio.vht_mcs_set[0] | (radio.vht_mcs_set[1] << 8);
    tlv->flags1().max_num_of_supported_tx_spatial_streams = 0; // TODO: Compute value (#1163)
    tlv->flags1().max_num_of_supported_rx_spatial_streams = 0; // TODO: Compute value (#1163)
    tlv->flags1().short_gi_support_80mhz                  = radio.vht_capability & BIT(5);
    tlv->flags1().short_gi_support_160mhz_and_80_80mhz    = radio.vht_capability & BIT(6);
    tlv->flags2().vht_support_80_80mhz                    = ((radio.vht_capability >> 2) & 3) == 2;
    tlv->flags2().vht_support_160mhz                      = ((radio.vht_capability >> 2) & 3) == 1;
    tlv->flags2().su_beamformer_capable                   = radio.vht_capability & BIT(11);
    tlv->flags2().mu_beamformer_capable                   = radio.vht_capability & BIT(19);

    return true;
}

bool CapabilityReportingTask::add_ap_he_capabilities(const AgentDB::sRadio &radio)
{
    if (!radio.he_supported) {
        return true;
    }

    auto tlv = m_cmdu_tx.addClass<wfa_map::tlvApHeCapabilities>();
    if (!tlv) {
        LOG(ERROR) << "Error creating TLV_AP_HE_CAPABILITIES";
        return false;
    }

    tlv->radio_uid() = radio.front.iface_mac;

    // TODO: Fetch the AP HE Capabilities from the Wi-Fi driver via the Netlink socket and include
    // them into AP HE Capabilities TLV (#1162)

    return true;
}

} // namespace beerocks
