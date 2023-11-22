/* SPDX-License-Identifier: BSD-2-Clause-Patent
*
* SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
*
* This code is subject to the terms of the BSD+Patent license.
* See LICENSE file for more details.
*/

#include <bpl/bpl_service_prio_utils.h>

namespace beerocks {
namespace bpl {

enum routing_direction {
    PREROUTING,
    POSTROUTING,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *routing_direction_str(routing_direction enum_value) {
    switch (enum_value) {
    case PREROUTING:  return "PREROUTING";
    case POSTROUTING: return "POSTROUTING";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, routing_direction value) { return out << routing_direction_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum ebtables_remove_action {
    FLUSH_RULE,
    DELETE_RULE,
    DELETE_CHAIN,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *ebtables_remove_action_str(ebtables_remove_action enum_value) {
    switch (enum_value) {
    case FLUSH_RULE:   return "FLUSH_RULE";
    case DELETE_RULE:  return "DELETE_RULE";
    case DELETE_CHAIN: return "DELETE_CHAIN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, ebtables_remove_action value) { return out << ebtables_remove_action_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

class ServicePrioritizationUtils_cgr_mxl : public ServicePrioritizationUtils {
    virtual bool flush_rules() override;
    virtual bool apply_single_value_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                        uint8_t pcp) override;
    virtual bool apply_dscp_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                struct sDscpMap *map, uint8_t default_pcp = 0) override;
    virtual bool apply_up_map(std::list<struct sInterfaceTagInfo> *iface_list,
                              uint8_t default_pcp = 0) override;

    std::string dscp_proc_file_name    = "/proc/dscp-prio-table";
    std::string PREROUTING_CHAIN_NAME  = "service_prio_in";
    std::string POSTROUTING_CHAIN_NAME = "service_prio_out";
};

} // namespace bpl
} // namespace beerocks
