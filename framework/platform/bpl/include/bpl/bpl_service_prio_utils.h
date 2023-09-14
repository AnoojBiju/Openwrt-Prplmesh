/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _SERVICE_PRIORITIZATION_UTILS_H_
#define _SERVICE_PRIORITIZATION_UTILS_H_

#include <cstdint>
#include <list>
#include <memory>
#include <string>

namespace beerocks {
namespace bpl {

class ServicePrioritizationUtils {
public:
    enum ePortMode { UNTAGGED_PORT, TAGGED_PORT_PRIMARY_UNTAGGED, TAGGED_PORT_PRIMARY_TAGGED };
    // Enum AutoPrint generated code snippet begining- DON'T EDIT!
    // clang-format off
    static const char *ePortMode_str(ePortMode enum_value) {
        switch (enum_value) {
        case UNTAGGED_PORT:                return "UNTAGGED_PORT";
        case TAGGED_PORT_PRIMARY_UNTAGGED: return "TAGGED_PORT_PRIMARY_UNTAGGED";
        case TAGGED_PORT_PRIMARY_TAGGED:   return "TAGGED_PORT_PRIMARY_TAGGED";
        }
        static std::string out_str = std::to_string(int(enum_value));
        return out_str.c_str();
    }
    friend inline std::ostream &operator<<(std::ostream &out, ePortMode value) { return out << ePortMode_str(value); }
    // clang-format on
    // Enum AutoPrint generated code snippet end
    struct sInterfaceTagInfo {
        std::string iface_name;
        enum ePortMode tag_info;
    };

    virtual bool flush_rules() { return false; }
    virtual bool apply_single_value_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                        uint8_t pcp)
    {
        return false;
    }
    virtual bool apply_dscp_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                uint8_t default_pcp = 0)
    {
        return false;
    }
    virtual bool apply_up_map(std::list<struct sInterfaceTagInfo> *iface_list,
                              uint8_t default_pcp = 0)
    {
        return false;
    }
};

std::shared_ptr<ServicePrioritizationUtils> register_service_prio_utils();

} // namespace bpl

} // namespace beerocks

#endif // _SERVICE_PRIORITIZATION_TASK_H_
