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

class ServicePrioritizationUtils_cgr_mxl : public ServicePrioritizationUtils {
    virtual bool flush_rules() override;
    virtual bool apply_single_value_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                        uint8_t pcp) override;
    virtual bool apply_dscp_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                struct sDscpMap *map, uint8_t default_pcp = 0) override;
    virtual bool apply_up_map(std::list<struct sInterfaceTagInfo> *iface_list,
                              uint8_t default_pcp = 0) override;

    std::string dscp_proc_file_name = "/proc/dscp-prio-table";
};

} // namespace bpl
} // namespace beerocks
