/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "service_prioritization_task.h"
#include "../agent_db.h"
#include "../son_slave_thread.h"
#include <beerocks/tlvf/beerocks_message_apmanager.h>

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bpl/bpl_service_prio_utils.h>
#include <tlvf/wfa_map/tlvDscpMappingTable.h>
#include <tlvf/wfa_map/tlvProfile2ErrorCode.h>

namespace beerocks {
using namespace net;

ServicePrioritizationTask::ServicePrioritizationTask(slave_thread &btl_ctx,
                                                     ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::SERVICE_PRIORITIZATION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
    service_prio_utils = bpl::register_service_prio_utils();
    if (!service_prio_utils) {
        LOG(ERROR) << "failed to register service prio utils";
    }
}

bool ServicePrioritizationTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                            uint32_t iface_index, const sMacAddr &dst_mac,
                                            const sMacAddr &src_mac, int fd,
                                            std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::SERVICE_PRIORITIZATION_REQUEST_MESSAGE: {
        handle_service_prioritization_request(cmdu_rx, src_mac);
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void ServicePrioritizationTask::handle_service_prioritization_request(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    LOG(DEBUG) << "Received SERVICE_PRIORITIZATION_REQUEST_MESSAGE, mid=" << std::hex << mid;

    m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);

    LOG(DEBUG) << "Sending ACK message to the originator, mid=" << std::hex << mid;
    m_btl_ctx.send_cmdu_to_controller({}, m_cmdu_tx);

    auto service_prioritization_rules =
        cmdu_rx.getClassList<wfa_map::tlvServicePrioritizationRule>();

    // Split rules to lists of rules to remove and rules to add.
    // If rule is being added, but it already exist only overwite it.
    std::vector<std::shared_ptr<wfa_map::tlvServicePrioritizationRule>> rules_to_remove;
    std::vector<std::shared_ptr<wfa_map::tlvServicePrioritizationRule>> rules_to_add;
    auto db = AgentDB::get();
    for (auto &rule : service_prioritization_rules) {
        LOG(DEBUG) << "Service Prioritization Rule TLV Dump" << std::endl
                   << "Rule id=" << rule->rule_params().id << std::endl
                   << "add_remove=" << rule->rule_params().bits_field1.add_remove << std::endl
                   << "precedence=" << rule->rule_params().precedence << std::endl
                   << "output=" << rule->rule_params().output << std::endl
                   << "always_match=" << rule->rule_params().bits_field2.always_match;
        // Remove
        if (!rule->rule_params().bits_field1.add_remove) {
            rules_to_remove.push_back(rule);
            continue;
        }

        auto rule_found_it = db->service_prioritization.rules.find(rule->rule_params().id);

        // Overwrite existing rule
        if (rule_found_it != db->service_prioritization.rules.end()) {
            rule_found_it->second = rule->rule_params();
            continue;
        }

        // Rule to Add
        rules_to_add.push_back(rule);
    }

    // Prepare error response message, in case we will need to fill it.
    if (!m_cmdu_tx.create(0, ieee1905_1::eMessageType::ERROR_RESPONSE_MESSAGE)) {
        LOG(ERROR) << "CMDU creation has failed";
        return;
    }

    for (const auto &rule_to_remove : rules_to_remove) {
        auto rule_found_it =
            db->service_prioritization.rules.find(rule_to_remove->rule_params().id);
        if (rule_found_it != db->service_prioritization.rules.end()) {
            db->service_prioritization.rules.erase(rule_found_it);
            continue;
        }
        // If we were asked to remove a rule we don't have, add Profile-2 Error Code TLV.
        auto profile2_error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2ErrorCode>();
        if (!profile2_error_code_tlv) {
            LOG(ERROR) << "addClass has failed";
            return;
        }
        profile2_error_code_tlv->reason_code() =
            wfa_map::tlvProfile2ErrorCode::eReasonCode::SERVICE_PRIORITIZATION_RULE_NOT_FOUND;
        profile2_error_code_tlv->set_service_prioritization_rule_id(
            rule_to_remove->rule_params().id);
    }

    for (const auto &rule_to_add : rules_to_add) {
        // '1' is the current maximum allowed ruled specified in the
        // tlvProfile2ApCapability::max_prioritization_rules
        if (db->service_prioritization.rules.size() >= db->device_conf.max_prioritization_rules) {
            auto profile2_error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2ErrorCode>();
            if (!profile2_error_code_tlv) {
                LOG(ERROR) << "addClass has failed";
                return;
            }
            profile2_error_code_tlv->reason_code() = wfa_map::tlvProfile2ErrorCode::
                NUMBER_OF_SERVICE_PRIORITIZATION_RULES_EXCEEDED_THE_MAXIMUM_SUPPORTED;
            profile2_error_code_tlv->set_service_prioritization_rule_id(
                rule_to_add->rule_params().id);
            break;
        }

        db->service_prioritization.rules[rule_to_add->rule_params().id] =
            rule_to_add->rule_params();
    }

    // If added Profile2ErrorCode TLVs, send the ERROR_RESPONSE_MESSAGE.
    if (m_cmdu_tx.getClass<wfa_map::tlvProfile2ErrorCode>()) {
        m_btl_ctx.send_cmdu_to_controller({}, m_cmdu_tx);
    }

    auto dscp_mapping_table_tlv = cmdu_rx.getClass<wfa_map::tlvDscpMappingTable>();
    if (dscp_mapping_table_tlv) {
        auto dscp_mapping_table = dscp_mapping_table_tlv->dscp_pcp_mapping(0);
        std::copy(dscp_mapping_table, dscp_mapping_table + 64,
                  db->service_prioritization.dscp_mapping_table.begin());
    }

    if (!qos_apply_active_rule()) {
        LOG(ERROR) << "Failed setting up QoS active rule";
    }
}

void ServicePrioritizationTask::gather_iface_details(
    std::list<bpl::ServicePrioritizationUtils::sInterfaceTagInfo> *iface_tag_info_list)
{
    auto db                                                  = AgentDB::get();
    bpl::ServicePrioritizationUtils::sInterfaceTagInfo iface = {};

    // bridge interface is configured as Primary VLAN ID untagged Port with primary VLAN ID
    iface.iface_name = db->bridge.iface_name;
    iface.tag_info   = bpl::ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_UNTAGGED;
    iface_tag_info_list->push_back(iface);

    // Update WAN and LAN Ports.
    if (!db->device_conf.local_gw && !db->ethernet.wan.iface_name.empty()) {
        iface.iface_name = db->ethernet.wan.iface_name;
        iface.tag_info   = bpl::ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_UNTAGGED;
        iface_tag_info_list->push_back(iface);
    }
    for (const auto &lan_iface_info : db->ethernet.lan) {
        iface            = {0};
        iface.iface_name = lan_iface_info.iface_name;
        iface.tag_info   = bpl::ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_UNTAGGED;
        iface_tag_info_list->push_back(iface);
    }

    // Wireless Backhaul
    if (!db->device_conf.local_gw && !db->backhaul.selected_iface_name.empty() &&
        db->backhaul.connection_type == AgentDB::sBackhaul::eConnectionType::Wireless) {
        iface      = {};
        auto radio = db->radio(db->backhaul.selected_iface_name);
        if (!radio) {
            LOG(ERROR) << "Could not find Backhaul Radio interface!";
            return;
        }
        LOG(DEBUG) << "Inside wireless backhaul case, multi_ap_profile="
                   << db->backhaul.bssid_multi_ap_profile;
        iface.iface_name = radio->back.iface_name;
        iface.tag_info =
            db->backhaul.bssid_multi_ap_profile > 1
                ? bpl::ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_TAGGED
                : bpl::ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT;
        iface_tag_info_list->push_back(iface);
    }

    for (auto radio : db->get_radios_list()) {
        if (!radio) {
            continue;
        }

        for (const auto &bss : radio->front.bssids) {
            // Skip unconfigured BSS.
            if (bss.ssid.empty()) {
                continue;
            }
            iface = {};

            LOG(DEBUG) << "BSS " << bss.mac << ", ssid:" << bss.ssid;

            std::string bss_iface;

            if (!network_utils::linux_iface_get_name(bss.mac, bss_iface)) {
                LOG(WARNING) << "Interface with MAC " << bss.mac << " does not exist";
                continue;
            }

            if (bss.fronthaul_bss && !bss.backhaul_bss) { // fBSS
                iface.iface_name = bss_iface;
                iface.tag_info   = bpl::ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT;
                iface_tag_info_list->push_back(iface);
            } else if (!bss.fronthaul_bss && bss.backhaul_bss) { // bBSS
                auto bss_iface_netdevs =
                    network_utils::get_bss_ifaces(bss_iface, db->bridge.iface_name);

                for (const auto &bss_iface_netdev : bss_iface_netdevs) {
                    iface.iface_name = bss_iface_netdev;
                    iface.tag_info =
                        bss.backhaul_bss_disallow_profile1_agent_association
                            ? bpl::ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_TAGGED
                            : bpl::ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT;
                    iface_tag_info_list->push_back(iface);
                    LOG(DEBUG) << "Inside for loop bBSS case, disallow="
                               << bss.backhaul_bss_disallow_profile1_agent_association;
                    LOG(DEBUG) << "BSS " << iface.iface_name << " tag_info " << iface.tag_info;
                }
            } else { // Combined fBSS & bBSS - Currently Support only Profile-1 (PPM-1418)
                LOG(DEBUG) << "in else case BSS= " << bss_iface;
                iface.iface_name = bss_iface;
                iface.tag_info   = bpl::ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT;
                iface_tag_info_list->push_back(iface);

                auto bss_iface_netdevs =
                    network_utils::get_bss_ifaces(bss_iface, db->bridge.iface_name);

                for (const auto &bss_iface_netdev : bss_iface_netdevs) {
                    LOG(DEBUG) << "in else case for loop BSS= " << bss_iface_netdev;
                    iface.iface_name = bss_iface_netdev;
                    iface.tag_info   = bpl::ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT;
                    iface_tag_info_list->push_back(iface);
                }
            }
        }
    }
}

bool ServicePrioritizationTask::qos_apply_active_rule()
{
    const auto &rules = AgentDB::get()->service_prioritization.rules;
    auto it           = rules.cbegin();
    auto active       = rules.cend();
    while (it != rules.cend()) {
        if (it->second.bits_field2.always_match) {
            if ((active == rules.cend()) || (active->second.precedence < it->second.precedence)) {
                active = it;
            }
        }
        ++it;
    }
    if (active != rules.cend()) {
        if (!service_prio_utils) {
            LOG(ERROR) << "Service Priority Utilities are not found";
            return false;
        }
        auto db                                      = AgentDB::get();
        beerocks_message::sServicePrioConfig request = {};
        request.mode                                 = active->second.output;
        std::copy(db->service_prioritization.dscp_mapping_table.begin(),
                  db->service_prioritization.dscp_mapping_table.end(), request.data);
        beerocks::ServicePrioritizationTask::send_service_prio_config(request);
        switch (active->second.output) {
        case QOS_USE_DSCP_MAP:
            return qos_setup_dscp_map();
        case QOS_USE_UP:
            return qos_setup_up_map();
        default:
            return qos_setup_single_value_map(active->second.output);
        }
    }

    return true;
}

bool ServicePrioritizationTask::qos_flush_setup()
{
    //TODO: PPM-2389, drive ebtables or external software
    // as per vendor specific in the Service Prioritization utility
    return service_prio_utils->flush_rules();
}

bool ServicePrioritizationTask::qos_setup_single_value_map(uint8_t pcp)
{
    if (pcp >= QOS_USE_DSCP_MAP) {
        LOG(ERROR) << "invalid output value for QoS single rule (" << static_cast<uint16_t>(pcp)
                   << ')';
        return false;
    }

    if (qos_flush_setup() == false) {
        return false;
    }

    std::list<bpl::ServicePrioritizationUtils::sInterfaceTagInfo> iface_list;
    ServicePrioritizationTask::gather_iface_details(&iface_list);

    //TODO: PPM-2389, drive ebtables or external software
    // as per vendor specific in the Service Prioritization utility
    return service_prio_utils->apply_single_value_map(&iface_list, pcp);
}

bool ServicePrioritizationTask::qos_setup_dscp_map()
{
    uint8_t pcp = 0;
    std::list<bpl::ServicePrioritizationUtils::sInterfaceTagInfo> iface_list;
    bpl::ServicePrioritizationUtils::sDscpMap dscp_map = {};
    auto db                                            = AgentDB::get();

    LOG(DEBUG) << "ServicePrioritizationTask::qos_setup_dscp_map - DSCP custom map used for PCP";

    pcp = db->traffic_separation.default_pcp;
    LOG(DEBUG) << "Default PCP = " << pcp;

    ServicePrioritizationTask::gather_iface_details(&iface_list);
    std::copy(db->service_prioritization.dscp_mapping_table.begin(),
              db->service_prioritization.dscp_mapping_table.end(), dscp_map.dscp);

    qos_flush_setup();

    //TODO: PPM-2389, drive ebtables or external software
    // as per vendor specific in the Service Prioritization utility
    return service_prio_utils->apply_dscp_map(&iface_list, &dscp_map, pcp);
}

bool ServicePrioritizationTask::qos_setup_up_map()
{
    LOG(DEBUG) << "ServicePrioritizationTask::qos_setup_up_map - UP used for PCP";

    qos_flush_setup();

    uint8_t pcp = AgentDB::get()->traffic_separation.default_pcp;
    std::list<bpl::ServicePrioritizationUtils::sInterfaceTagInfo> iface_list;
    ServicePrioritizationTask::gather_iface_details(&iface_list);

    //TODO: PPM-2389, drive ebtables or external software
    // as per vendor specific in the Service Prioritization utility
    return service_prio_utils->apply_up_map(&iface_list, pcp);
}

bool ServicePrioritizationTask::send_service_prio_config(
    const beerocks_message::sServicePrioConfig &request)
{
    // Sending the config to all AP managers
    m_btl_ctx.m_radio_managers.do_on_each_radio_manager(
        [&](slave_thread::sManagedRadio &radio_manager,
            const std::string &fronthaul_iface) -> bool {
            auto request_msg = message_com::create_vs_message<
                beerocks_message::cACTION_APMANAGER_HOSTAP_SERVICE_PRIO_CONFIG>(m_cmdu_tx);

            if (!request_msg) {
                LOG(ERROR)
                    << "Failed to build cACTION_APMANAGER_HOSTAP_SERVICE_PRIO_CONFIG message";
                return false;
            }

            request_msg->cs_params().mode = request.mode;
            std::copy(request.data, request.data + beerocks::message::DSCP_MAPPING_LIST_LENGTH,
                      request_msg->cs_params().data);
            LOG(DEBUG) << "Sending service priority config to radio, mode: " << request.mode;

            m_btl_ctx.send_cmdu(radio_manager.ap_manager_fd, m_cmdu_tx);
            return true;
        });
    return true;
}

} // namespace beerocks
