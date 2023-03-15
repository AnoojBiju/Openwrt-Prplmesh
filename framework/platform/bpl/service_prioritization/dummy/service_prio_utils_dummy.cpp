/* SPDX-License-Identifier: BSD-2-Clause-Patent
*
* SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
*
* This code is subject to the terms of the BSD+Patent license.
* See LICENSE file for more details.
*/


#include "service_prio_utils_dummy.h"
#include <easylogging++.h>

namespace beerocks {
namespace bpl {

bool ServicePrioritizationUtils_dummy::flush_rules()
{
    LOG(ERROR) << __func__ << ":not Supported in Dummy";
    return false;
}

bool ServicePrioritizationUtils_dummy::apply_single_value_map(uint8_t pcp)
{
    LOG(ERROR) << __func__ << ":not Supported in Dummy";
    return false;
}

bool ServicePrioritizationUtils_dummy::apply_dscp_map()
{
    LOG(ERROR) << __func__ << ":not Supported in Dummy";
    return false;
}

bool ServicePrioritizationUtils_dummy::apply_up_map()
{
    LOG(ERROR) << __func__ << ":not Supported in Dummy";
    return false;
}

std::shared_ptr<ServicePrioritizationUtils> register_service_prio_utils()
{
    return std::make_shared<bpl::ServicePrioritizationUtils_dummy>();
}

} // namespace bpl

} // namespace beerocks
