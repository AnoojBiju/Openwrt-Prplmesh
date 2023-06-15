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
#include <memory>

namespace beerocks {
namespace bpl {

class ServicePrioritizationUtils {
public:
    enum ePortMode { UNTAGGED_PORT, TAGGED_PORT_PRIMARY_UNTAGGED, TAGGED_PORT_PRIMARY_TAGGED };
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
