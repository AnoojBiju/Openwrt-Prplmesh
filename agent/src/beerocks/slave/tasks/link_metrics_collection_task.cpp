/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "link_metrics_collection_task.h"

#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

#include <beerocks/tlvf/beerocks_message_backhaul.h>

#include <tlvf/ieee_1905_1/tlvLinkMetricQuery.h>
#include <tlvf/ieee_1905_1/tlvLinkMetricResultCode.h>
#include <tlvf/ieee_1905_1/tlvReceiverLinkMetric.h>
#include <tlvf/ieee_1905_1/tlvTransmitterLinkMetric.h>
#include <tlvf/wfa_map/tlvApMetricQuery.h>
#include <tlvf/wfa_map/tlvBeaconMetricsQuery.h>
#include <tlvf/wfa_map/tlvStaMacAddressType.h>

namespace beerocks {

LinkMetricsCollectionTask::LinkMetricsCollectionTask(backhaul_manager &btl_ctx,
                                                     ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::LINK_METRICS_COLLECTION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool LinkMetricsCollectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                            const sMacAddr &src_mac,
                                            std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::LINK_METRIC_QUERY_MESSAGE: {
        handle_link_metric_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::COMBINED_INFRASTRUCTURE_METRICS_MESSAGE: {
        handle_combined_infrastructure_metrics(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::BEACON_METRICS_QUERY_MESSAGE: {
        handle_beacon_metrics_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE: {
        handle_associated_sta_link_metrics_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::AP_METRICS_QUERY_MESSAGE: {
        handle_ap_metrics_query(cmdu_rx, src_mac);
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void LinkMetricsCollectionTask::work() {}

void LinkMetricsCollectionTask::handle_link_metric_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                         const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received LINK_METRIC_QUERY_MESSAGE, mid=" << std::hex << mid;

    /**
     * The IEEE 1905.1 standard says about the Link Metric Query TLV and the neighbor type octet
     * that "If the value is 0, then the EUI48 field is not present; if the value is 1, then the
     * EUI-48 field shall be present."
     *
     * However, optional fields are not currently supported by TLVF.
     *
     * As a workaround, instead of defining a tlvLinkMetricQuery TLV with an optional field, we
     * have defined two different TLVs: tlvLinkMetricQuery with the optional field and
     * tlvLinkMetricQueryAllNeighbors without it. Application must check which of both TLVs has
     * been received inside the message.
     */
    std::shared_ptr<ieee1905_1::tlvLinkMetricQueryAllNeighbors> tlvLinkMetricQueryAllNeighbors;
    std::shared_ptr<ieee1905_1::tlvLinkMetricQuery> tlvLinkMetricQuery;

    tlvLinkMetricQueryAllNeighbors = cmdu_rx.getClass<ieee1905_1::tlvLinkMetricQueryAllNeighbors>();
    if (!tlvLinkMetricQueryAllNeighbors) {
        tlvLinkMetricQuery = cmdu_rx.getClass<ieee1905_1::tlvLinkMetricQuery>();
        if (!tlvLinkMetricQuery) {
            LOG(ERROR) << "getClass ieee1905_1::tlvLinkMetricQueryAllNeighbors and "
                          "ieee1905_1::tlvLinkMetricQuery failed";
            return;
        }
    }

    auto db = AgentDB::get();

    /**
     * 1905.1 AL MAC address of the device that transmits the response message.
     */
    sMacAddr reporter_al_mac = db->bridge.mac;

    /**
     * 1905.1 AL MAC address of a neighbor of the receiving device.
     * Query can specify a particular neighbor device or all neighbor devices.
     */
    sMacAddr neighbor_al_mac = net::network_utils::ZERO_MAC;

    /**
     * Obtain link metrics for either all neighbors or a specific neighbor
     */
    ieee1905_1::eLinkMetricNeighborType neighbor_type;

    /**
     * The link metrics type requested: TX, RX or both
     */
    ieee1905_1::eLinkMetricsType link_metrics_type;

    if (tlvLinkMetricQuery) {
        /**
         * If tlvLinkMetricQuery has been included in message, we will be permissive enough to
         * allow it specify ALL_NEIGHBORS and if so, then we will just ignore the field
         * containing the MAC address of neighbor.
         */
        neighbor_type     = tlvLinkMetricQuery->neighbor_type();
        neighbor_al_mac   = tlvLinkMetricQuery->mac_al_1905_device();
        link_metrics_type = tlvLinkMetricQuery->link_metrics_type();
    } else {
        neighbor_type = tlvLinkMetricQueryAllNeighbors->neighbor_type();
        if (ieee1905_1::eLinkMetricNeighborType::ALL_NEIGHBORS != neighbor_type) {
            LOG(ERROR) << "Unexpected neighbor type: " << std::hex << int(neighbor_type);
            return;
        }
        link_metrics_type = tlvLinkMetricQueryAllNeighbors->link_metrics_type();
    }

    /**
     * Set alias flag to true if link metrics for a specific neighbor have been requested
     */
    bool specific_neighbor =
        ieee1905_1::eLinkMetricNeighborType::SPECIFIC_NEIGHBOR == neighbor_type;

    /**
     * Create response message
     */
    auto cmdu_tx_header =
        m_cmdu_tx.create(mid, ieee1905_1::eMessageType::LINK_METRIC_RESPONSE_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "Failed creating LINK_METRIC_RESPONSE_MESSAGE header! mid=" << std::hex
                   << mid;
        return;
    }

    /**
     * Get the list of neighbor links from the topology database.
     * Neighbors are grouped by the interface that connects to them.
     */
    std::map<backhaul_manager::sLinkInterface, std::vector<backhaul_manager::sLinkNeighbor>>
        neighbor_links_map;
    if (!m_btl_ctx.get_neighbor_links(neighbor_al_mac, neighbor_links_map)) {
        LOG(ERROR) << "Failed to get the list of neighbor links";
        return;
    }

    /**
     * If the specified neighbor 1905.1 AL ID does not identify a neighbor of the receiving 1905.1
     * AL, then a link metric ResultCode TLV (see Table 6-21) with a value set to “invalid
     * neighbor” shall be included in this message.
     */
    bool invalid_neighbor = specific_neighbor && neighbor_links_map.empty();
    if (invalid_neighbor) {
        auto tlvLinkMetricResultCode = m_cmdu_tx.addClass<ieee1905_1::tlvLinkMetricResultCode>();
        if (!tlvLinkMetricResultCode) {
            LOG(ERROR) << "addClass ieee1905_1::tlvLinkMetricResultCode failed, mid=" << std::hex
                       << mid;
            return;
        }

        LOG(INFO) << "Invalid neighbor 1905.1 AL ID specified: " << neighbor_al_mac;

        tlvLinkMetricResultCode->value() = ieee1905_1::tlvLinkMetricResultCode::INVALID_NEIGHBOR;

        LOG(DEBUG) << "Sending LINK_METRIC_RESPONSE_MESSAGE (invalid neighbour), mid: " << std::hex
                   << mid;
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                      tlvf::mac_to_string(db->bridge.mac));
        return;
    }

    /**
     * Report link metrics for the link with specific neighbor or for all neighbors, as
     * obtained from topology database
     */
    for (const auto &entry : neighbor_links_map) {
        auto interface        = entry.first;
        const auto &neighbors = entry.second;

        std::unique_ptr<link_metrics_collector> collector =
            m_btl_ctx.create_link_metrics_collector(interface);
        if (!collector) {
            continue;
        }

        for (const auto &neighbor : neighbors) {

            LOG(TRACE) << "Getting link metrics for interface " << interface.iface_name
                       << " (MediaType = " << std::hex << (int)interface.media_type
                       << ") and neighbor " << neighbor.iface_mac;

            sLinkMetrics link_metrics;
            if (!collector->get_link_metrics(interface.iface_name, neighbor.iface_mac,
                                             link_metrics)) {
                LOG(ERROR) << "Unable to get link metrics for interface " << interface.iface_name
                           << " and neighbor " << neighbor.iface_mac;
                return;
            }

            if (!m_btl_ctx.add_link_metrics(reporter_al_mac, interface, neighbor, link_metrics,
                                            link_metrics_type)) {
                return;
            }
        }
    }

    LOG(DEBUG) << "Sending LINK_METRIC_RESPONSE_MESSAGE, mid: " << std::hex << mid;
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_combined_infrastructure_metrics(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received COMBINED_INFRASTRUCTURE_METRICS message, mid=" << std::hex << mid;

    if (cmdu_rx.getClass<ieee1905_1::tlvReceiverLinkMetric>())
        LOG(DEBUG) << "Received TLV_RECEIVER_LINK_METRIC";
    if (cmdu_rx.getClass<ieee1905_1::tlvTransmitterLinkMetric>())
        LOG(DEBUG) << "Received TLV_TRANSMITTER_LINK_METRIC";

    // build ACK message CMDU
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return;
    }
    LOG(DEBUG) << "sending ACK message to the originator, mid=" << std::hex << mid;
    auto db = AgentDB::get();
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_beacon_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                            const sMacAddr &src_mac)
{
    LOG(DEBUG) << "now going to handle BEACON METRICS QUERY";

    // extract the desired STA mac
    auto tlvBeaconMetricsQuery = cmdu_rx.getClass<wfa_map::tlvBeaconMetricsQuery>();
    if (!tlvBeaconMetricsQuery) {
        LOG(ERROR) << "handle_1905_beacon_metrics_query should handle only tlvBeaconMetrics, but "
                      "got something else: 0x"
                   << std::hex << (uint16_t)cmdu_rx.getMessageType();
        return;
    }

    const sMacAddr &requested_sta_mac = tlvBeaconMetricsQuery->associated_sta_mac();
    LOG(DEBUG) << "the requested STA mac is: " << requested_sta_mac;

    // build ACK message CMDU
    const auto mid      = cmdu_rx.getMessageId();
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return;
    }

    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(requested_sta_mac, AgentDB::eMacType::CLIENT);
    if (!radio) {
        LOG(DEBUG) << "STA with MAC [" << requested_sta_mac
                   << "] is not associated with any BSS operated by the agent";

        // add an Error Code TLV
        auto error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvErrorCode>();
        if (!error_code_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvErrorCode has failed";
            return;
        }

        error_code_tlv->reason_code() =
            wfa_map::tlvErrorCode::STA_NOT_ASSOCIATED_WITH_ANY_BSS_OPERATED_BY_THE_AGENT;

        error_code_tlv->sta_mac() = requested_sta_mac;

        // report the error
        std::stringstream errorSS;
        auto error_tlv = m_cmdu_tx.getClass<wfa_map::tlvErrorCode>();
        if (error_tlv) {
            errorSS << "0x" << error_tlv->reason_code();
        } else {
            errorSS << "note: error constructing the error itself";
        }

        LOG(DEBUG) << "sending ACK message to the originator with an error, mid: " << std::hex
                   << mid << " tlv error code: " << errorSS.str();

        // send the error
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                      tlvf::mac_to_string(db->bridge.mac));
        return;
    }

    auto radio_info = m_btl_ctx.get_radio(radio->front.iface_mac);
    if (!radio_info) {
        LOG(ERROR) << "Failed to get radio info for " << radio->front.iface_mac;
        return;
    }

    LOG(DEBUG) << "Found the radio that has the sation. radio: " << radio->front.iface_mac
               << "; station: " << requested_sta_mac;

    LOG(DEBUG) << "BEACON METRICS QUERY: sending ACK message to the originator mid: " << std::hex
               << mid; // USED IN TESTS

    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_associated_sta_link_metrics_query(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE , mid=" << std::dec
               << int(mid);

    if (!m_cmdu_tx.create(mid,
                          ieee1905_1::eMessageType::ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE)) {
        LOG(ERROR)
            << "cmdu creation of type ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE, has failed";
        return;
    }

    auto mac = cmdu_rx.getClass<wfa_map::tlvStaMacAddressType>();
    if (!mac) {
        LOG(ERROR) << "Failed to get mac address";
        return;
    }

    auto assoc_link_metrics = m_cmdu_tx.addClass<wfa_map::tlvAssociatedStaLinkMetrics>();
    if (!assoc_link_metrics) {
        LOG(ERROR) << "Failed to create tlvAssociatedStaLinkMetrics tlv";
        return;
    }

    auto db = AgentDB::get();

    // Check if it is an error scenario - if the STA specified in the STA link Query message is not associated
    // with any of the BSS operated by the Multi-AP Agent
    auto radio = db->get_radio_by_mac(mac->sta_mac(), AgentDB::eMacType::CLIENT);
    if (!radio) {
        LOG(ERROR) << "client with mac address " << mac->sta_mac() << " not found";
        //Add an Error Code TLV
        auto error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvErrorCode>();
        if (!error_code_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvErrorCode has failed";
            return;
        }
        error_code_tlv->reason_code() =
            wfa_map::tlvErrorCode::STA_NOT_ASSOCIATED_WITH_ANY_BSS_OPERATED_BY_THE_AGENT;
        error_code_tlv->sta_mac() = mac->sta_mac();

        LOG(DEBUG) << "Send a ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE back to controller";
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                      tlvf::mac_to_string(db->bridge.mac));
        return;
    }
    auto client_it = radio->associated_clients.find(mac->sta_mac());
    if (client_it == radio->associated_clients.end()) {
        LOG(ERROR) << "Cannot find sta sta " << mac->sta_mac();
        return;
    }
    if (client_it->second.bssid == net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Cannot find sta bssid";
        return;
    }
    LOG(DEBUG) << "Client with mac address " << mac->sta_mac() << " connected to "
               << client_it->second.bssid;

    auto request_out = message_com::create_vs_message<
        beerocks_message::cACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST>(m_cmdu_tx, mid);

    if (!request_out) {
        LOG(ERROR) << "Failed to build ACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST";
        return;
    }

    request_out->sync()    = true;
    request_out->sta_mac() = mac->sta_mac();

    auto radio_info = m_btl_ctx.get_radio(radio->front.iface_mac);
    if (!radio_info) {
        LOG(ERROR) << "Failed to get radio info for " << radio->front.iface_mac;
        return;
    }
    message_com::send_cmdu(radio_info->slave, m_cmdu_tx);
}

void LinkMetricsCollectionTask::handle_ap_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                        const sMacAddr &src_mac)
{
    const auto mid           = cmdu_rx.getMessageId();
    auto ap_metric_query_tlv = cmdu_rx.getClass<wfa_map::tlvApMetricQuery>();
    if (!ap_metric_query_tlv) {
        LOG(ERROR) << "AP Metrics Query CMDU mid=" << std::hex << mid
                   << " does not have AP Metric Query TLV";
        return;
    }

    std::unordered_set<sMacAddr> bssids;
    for (size_t bssid_idx = 0; bssid_idx < ap_metric_query_tlv->bssid_list_length(); bssid_idx++) {
        auto bssid_tuple = ap_metric_query_tlv->bssid_list(bssid_idx);
        if (!std::get<0>(bssid_tuple)) {
            LOG(ERROR) << "Failed to get bssid " << bssid_idx << " from AP_METRICS_QUERY";
            return;
        }
        bssids.insert(std::get<1>(bssid_tuple));
        LOG(DEBUG) << "Received AP_METRICS_QUERY_MESSAGE, mid=" << std::hex << mid << "  bssid "
                   << std::get<1>(bssid_tuple);
    }

    if (!m_btl_ctx.send_slave_ap_metric_query_message(mid, bssids)) {
        LOG(ERROR) << "Failed to forward AP_METRICS_RESPONSE to the son_slave_thread";
        return;
    }
}

} // namespace beerocks
