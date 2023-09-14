/* SPDX-License-Identifier: BSD-2-Clause-Patent
*
* SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
*
* This code is subject to the terms of the BSD+Patent license.
* See LICENSE file for more details.
*/

#include <bcl/beerocks_os_utils.h>
#include <bcl/beerocks_string_utils.h>
#include <easylogging++.h>

#include <bcl/beerocks_event_loop_impl.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

#include "service_prio_utils_osp_mxl.h"

namespace beerocks {
namespace bpl {

enum routing_direction {
    PREROUTING,
    POSTROUTING,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
const char *routing_direction_str(routing_direction enum_value) {
    switch (enum_value) {
    case PREROUTING:  return "PREROUTING";
    case POSTROUTING: return "POSTROUTING";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
std::ostream &operator<<(std::ostream &out, routing_direction value) { return out << routing_direction_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum ebtables_remove_action {
    FLUSH_RULE,
    DELETE_RULE,
    DELETE_CHAIN,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
const char *ebtables_remove_action_str(ebtables_remove_action enum_value) {
    switch (enum_value) {
    case FLUSH_RULE:   return "FLUSH_RULE";
    case DELETE_RULE:  return "DELETE_RULE";
    case DELETE_CHAIN: return "DELETE_CHAIN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
std::ostream &operator<<(std::ostream &out, ebtables_remove_action value) { return out << ebtables_remove_action_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

#define PREROUTING_CHAIN_NAME "service_prio_in"
#define POSTROUTING_CHAIN_NAME "service_prio_out"

void apply_ebtables_rules(std::string prerouting_chain_name, std::string postrouting_chain_name,
                          std::string iface_name, ServicePrioritizationUtils::ePortMode tag_mode,
                          uint8_t default_pcp)
{
    std::string cmd_preset = "ebtables -t nat -A ";
    std::string cmd;
    LOG(DEBUG) << "Apply rules for " << iface_name;
    cmd.reserve(200);

    // create custom chains
    cmd = "ebtables -t nat -N " + prerouting_chain_name;
    beerocks::os_utils::system_call(cmd);
    cmd = "ebtables -t nat -N " + postrouting_chain_name;
    beerocks::os_utils::system_call(cmd);

    cmd = cmd_preset + "PREROUTING -j " + prerouting_chain_name;
    beerocks::os_utils::system_call(cmd);
    cmd = cmd_preset + "POSTROUTING -j " + postrouting_chain_name;
    beerocks::os_utils::system_call(cmd);


    /* Below are the example commands for different tagged modes
TAGGED_PORT_PRIMARY_TAGGED
	Ingress
	ebtables -t nat -A service_prio_in -i sw_1 -p 802_1Q -j --set-pcp-prio
	Egress
	ebtables -t nat -A service_prio_out -o sw_1 -p 802_1Q -j prio --set-prio-pcp

TAGGED_PORT_PRIMARY_UNTAGGED
	Ingress
	ebtables -t nat -A service_prio_in -i wlan0.0 -j prio --set-prio 0
	ebtables -t nat -A service_prio_in -i wlan0.0 -p IPv4 -j prio --set-dscp-prio

UNTAGGED_PORT
	Ingress
	ebtables -t nat -A service_prio_in -i wlan0.0 -j prio --set-prio 0
	ebtables -t nat -A service_prio_in -i wlan0.0 -p IPv4 -j prio --set-dscp-prio
*/

    if (tag_mode == ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_TAGGED) {
        //ingress rule
        cmd = cmd_preset + prerouting_chain_name + " -i " + iface_name +
              "  -p 802_1Q -j --set-pcp-prio";
        beerocks::os_utils::system_call(cmd);

        //egress rule
        cmd = cmd_preset + postrouting_chain_name + " -o " + iface_name +
              " -p 802_1Q -j prio --set-prio-pcp";
        beerocks::os_utils::system_call(cmd);
    } else if ((tag_mode == ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_UNTAGGED) ||
               (tag_mode == ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT)) {
        //ingress rules
        cmd = cmd_preset + prerouting_chain_name + " -i " + iface_name + " -j prio --set-prio " +
              std::to_string(default_pcp);

        beerocks::os_utils::system_call(cmd);

        cmd = cmd_preset + prerouting_chain_name + " -i " + iface_name +
              " -p IPv4 -j prio --set-dscp-prio";
        beerocks::os_utils::system_call(cmd);
    }
}

void remove_ebtables_rules(std::string custom_chain_name, bool flush_rule, bool delete_rule,
                           bool delete_chain, enum routing_direction route)
{
    std::string cmd;

    LOG(DEBUG) << "Remove " << custom_chain_name << " rules";
    cmd.reserve(150);
    if (flush_rule) {
        cmd.assign("ebtables -t nat ").append("-F ");
        cmd.append(custom_chain_name);
        beerocks::os_utils::system_call(cmd);
    }
    if (delete_rule) {
        cmd.assign("ebtables -t nat ").append("-D ");
        if (route == PREROUTING) {
            cmd.append("prerouting ");
        } else if (route == POSTROUTING) {
            cmd.append("postrouting ");
        }
        cmd.append(custom_chain_name);
        beerocks::os_utils::system_call(cmd);
    }

    if (delete_chain) {
        cmd.assign("ebtables -t nat ").append("-X ");
        cmd.append(custom_chain_name);
        beerocks::os_utils::system_call(cmd);
    }
}

bool ServicePrioritizationUtils_osp_mxl::flush_rules()
{
    LOG(ERROR) << __func__ << ":Flushing ebtable rules";
    remove_ebtables_rules(PREROUTING_CHAIN_NAME, true, true, true, PREROUTING);
    remove_ebtables_rules(POSTROUTING_CHAIN_NAME, true, true, true, POSTROUTING);
    return true;
}

bool ServicePrioritizationUtils_osp_mxl::apply_single_value_map(
    std::list<struct sInterfaceTagInfo> *iface_list, uint8_t pcp)
{
    LOG(ERROR) << __func__ << ":not Supported in CGR";
    return false;
}

bool ServicePrioritizationUtils_osp_mxl::apply_dscp_map(
    std::list<struct sInterfaceTagInfo> *iface_list, uint8_t default_pcp)
{
    LOG(DEBUG) << __func__ << ":Applying Ebtables";
    LOG(DEBUG) << "Interface details are";
    for (auto itr = iface_list->rbegin(); itr != iface_list->rend(); itr++) {
        LOG(DEBUG) << "Iface name = " << itr->iface_name << ", type = " << itr->tag_info;
    }

    for (auto itr = iface_list->rbegin(); itr != iface_list->rend(); itr++) {
        apply_ebtables_rules(PREROUTING_CHAIN_NAME, POSTROUTING_CHAIN_NAME, itr->iface_name,
                             itr->tag_info, default_pcp);
    }

    return true;
}

bool ServicePrioritizationUtils_osp_mxl::apply_up_map(
    std::list<struct sInterfaceTagInfo> *iface_list, uint8_t default_pcp)
{
    LOG(ERROR) << __func__ << ":not Supported in CGR";
    return false;
}

std::shared_ptr<ServicePrioritizationUtils> register_service_prio_utils()
{
    return std::make_shared<bpl::ServicePrioritizationUtils_osp_mxl>();
}

} // namespace bpl

} // namespace beerocks
