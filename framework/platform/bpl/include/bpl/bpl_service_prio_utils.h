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
    virtual bool flush_rules() {
	  return false;
    }
    virtual bool apply_single_value_map(uint8_t pcp) {
	    return false;
    }
    virtual bool apply_dscp_map() {
	    return false;
    }
    virtual bool apply_up_map() {
	    return false;
    }
};

std::shared_ptr<ServicePrioritizationUtils> register_service_prio_utils();

} // namespace bpl

} // namespace beerocks

#endif // _SERVICE_PRIORITIZATION_TASK_H_
