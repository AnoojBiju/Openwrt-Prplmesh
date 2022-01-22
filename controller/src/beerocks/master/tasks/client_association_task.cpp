/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "client_association_task.h"
#include "../son_actions.h"

#include <bcl/beerocks_utils.h>
#include <bcl/son/son_assoc_frame_utils.h>
#include <tlvf/wfa_map/tlvClientAssociationEvent.h>
#include <tlvf/wfa_map/tlvClientCapabilityReport.h>
#include <tlvf/wfa_map/tlvClientInfo.h>

using namespace beerocks;
using namespace net;
using namespace son;

client_association_task::client_association_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                                 task_pool &tasks_, const std::string &task_name_)
    : task(task_name_), m_database(database_), m_cmdu_tx(cmdu_tx_), m_tasks(tasks_)
{
}

void client_association_task ::work() {}

bool client_association_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                                    ieee1905_1::CmduMessageRx &cmdu_rx)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::TOPOLOGY_NOTIFICATION_MESSAGE: {
        verify_sta_association(src_mac, cmdu_rx);
        break;
    }
    case ieee1905_1::eMessageType::CLIENT_CAPABILITY_REPORT_MESSAGE: {
        return handle_cmdu_1905_client_capability_report_message(src_mac, cmdu_rx);
    }
    default: {
        return false;
    }
    }
    return true;
}

bool client_association_task::verify_sta_association(const sMacAddr &src_mac,
                                                     ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto sta_assoc_tlv = cmdu_rx.getClass<wfa_map::tlvClientAssociationEvent>();

    if (!sta_assoc_tlv) {
        return false;
    }

    auto ambiorix_dm = m_database.get_ambiorix_obj();

    if (!ambiorix_dm) {
        LOG(ERROR) << "Failed to get Ambiorix datamodel";
        return false;
    }

    auto station = m_database.get_station(sta_assoc_tlv->client_mac());

    if (!station) {
        LOG(ERROR) << "station " << sta_assoc_tlv->client_mac() << " not found";
        return false;
    }

    if (sta_assoc_tlv->association_event() ==
        wfa_map::tlvClientAssociationEvent::eAssociationEvent::CLIENT_HAS_JOINED_THE_BSS) {
        station->assoc_timestamp = ambiorix_dm->get_datamodel_time_format();
        dm_add_sta_association_event(sta_assoc_tlv->client_mac(), sta_assoc_tlv->bssid());

        if (!send_sta_capability_query(src_mac, cmdu_rx)) {
            LOG(ERROR) << "Failed to send Client Capability Query.";
            return false;
        }
        return true;
    }
    return false;
}

bool client_association_task::send_sta_capability_query(const sMacAddr &src_mac,
                                                        ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto client_association_event_tlv = cmdu_rx.getClass<wfa_map::tlvClientAssociationEvent>();

    if (!client_association_event_tlv) {
        return false;
    }
    if (!m_cmdu_tx.create(0, ieee1905_1::eMessageType::CLIENT_CAPABILITY_QUERY_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type CLIENT_CAPABILITY_QUERY_MESSAGE, has failed";
        return false;
    }

    auto client_info_tlv = m_cmdu_tx.addClass<wfa_map::tlvClientInfo>();

    if (!client_info_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvClientInfo has failed";
        return false;
    }
    client_info_tlv->client_mac() = client_association_event_tlv->client_mac();
    client_info_tlv->bssid()      = client_association_event_tlv->bssid();
    son_actions::send_cmdu_to_agent(src_mac, m_cmdu_tx, m_database);
    return true;
}

bool client_association_task::handle_cmdu_1905_client_capability_report_message(
    const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto mid                          = cmdu_rx.getMessageId();
    auto client_capability_report_tlv = cmdu_rx.getClass<wfa_map::tlvClientCapabilityReport>();
    if (!client_capability_report_tlv) {
        LOG(ERROR) << "getClass wfa_map::tlvClientCapabilityReport has failed";
        return false;
    }

    std::string result_code =
        (client_capability_report_tlv->result_code() == wfa_map::tlvClientCapabilityReport::SUCCESS)
            ? "SUCCESS"
            : "FAILURE";

    auto client_info_tlv = cmdu_rx.getClass<wfa_map::tlvClientInfo>();
    if (!client_info_tlv) {
        LOG(ERROR) << "getClass wfa_map::tlvClientInfo failed";
        return false;
    }

    auto sta_mac = client_info_tlv->client_mac();

    //log the details so it can be checked in the test_flows
    LOG(INFO) << "Received CLIENT_CAPABILITY_REPORT_MESSAGE, mid=" << std::hex << int(mid)
              << ", Result Code= " << result_code << ", client MAC= " << sta_mac
              << ", BSSID= " << client_info_tlv->bssid();

    /*
     * The remote agent reports no client capability data so return here.
     */
    if (client_capability_report_tlv->result_code() !=
        wfa_map::tlvClientCapabilityReport::SUCCESS) {
        return true;
    }

    LOG(DEBUG) << "(Re)Association Request frame= "
               << beerocks::utils::dump_buffer(
                      client_capability_report_tlv->association_frame(),
                      client_capability_report_tlv->association_frame_length());

    /*
     * Client capability data is latest assoc/reassoc request frame data
     * so assume unknown assoc frame type to cover both cases.
     */
    auto assoc_frame =
        assoc_frame::AssocReqFrame::parse(client_capability_report_tlv->association_frame(),
                                          client_capability_report_tlv->association_frame_length());

    if (!assoc_frame) {
        LOG(ERROR) << "Failed to parse Association Request frame.";
        return false;
    }

    beerocks::message::sRadioCapabilities capabilities = {};
    auto result = son::assoc_frame_utils::get_station_capabilities_from_assoc_frame(assoc_frame,
                                                                                    capabilities);
    if (!result) {
        LOG(ERROR) << "Failed to parse station capabilities.";
        return false;
    }
    son::wireless_utils::print_station_capabilities(capabilities);

    // Save latest station capabilities to Station object
    auto sta_mac_str = tlvf::mac_to_string(sta_mac);
    result           = m_database.set_station_capabilities(sta_mac_str, capabilities);
    if (!result) {
        LOG(ERROR) << "Failed to save capabilities.";
        return false;
    }

    // Update the station's link bw with the received caps
    auto client_bw     = m_database.get_node_bw(sta_mac_str);
    auto client_bw_max = client_bw;
    if (son::wireless_utils::get_station_max_supported_bw(capabilities, client_bw_max)) {
        if (client_bw_max < client_bw) {
            m_database.update_node_bw(sta_mac, client_bw_max);
        }
    }

    auto station = m_database.get_station(sta_mac);
    auto sta_cap = station->m_sta_cap.add(client_info_tlv->client_mac());

    if (assoc_frame->fields_present.ht_capability) {
        sta_cap->sta_ht_cap     = assoc_frame->sta_ht_capability()->ht_cap_info();
        sta_cap->ht_cap_present = true;
    }
    if (assoc_frame->fields_present.vht_capability) {
        sta_cap->sta_vht_cap     = assoc_frame->sta_vht_capability()->vht_cap_info();
        sta_cap->vht_cap_present = true;
    }
    return true;
}

bool client_association_task::dm_add_sta_association_event(const sMacAddr &sta_mac,
                                                           const sMacAddr &bssid)
{
    // Add AssociationEventData data model object
    auto station = m_database.get_station(sta_mac);
    auto assoc_event_path =
        m_database.dm_add_association_event(bssid, sta_mac, station->assoc_timestamp);

    if (assoc_event_path.empty()) {
        LOG(ERROR) << "Failed to add AssociationEventData for sta: " << sta_mac;
        return false;
    }

    auto ambiorix_dm = m_database.get_ambiorix_obj();

    if (!ambiorix_dm) {
        LOG(ERROR) << "Failed to get Ambiorix datamodel";
        return false;
    }

    // Remove previous entry
    ambiorix_dm->remove_optional_subobject(assoc_event_path, "HTCapabilities");
    ambiorix_dm->remove_optional_subobject(assoc_event_path, "VHTCapabilities");

    // Add optional HT(VHT)Capabilities data model sub-object(s)
    auto sta_cap = station->m_sta_cap.get(sta_mac);

    if (!sta_cap) {
        LOG(WARNING) << "No sStaCap found for station: " << sta_mac;
        return false;
    }
    if (sta_cap->ht_cap_present) {
        m_database.dm_set_assoc_event_sta_ht_cap(assoc_event_path, sta_mac);
    }
    if (sta_cap->vht_cap_present) {
        m_database.dm_set_assoc_event_sta_vht_cap(assoc_event_path, sta_mac);
    }

    // TODO: Fill up HE Capabilities for AssociationEvent, PPM-567
    return true;
}
