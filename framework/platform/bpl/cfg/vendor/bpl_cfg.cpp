/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl/bpl_cfg.h>
#include <mapf/common/utils.h>

using namespace mapf;

namespace beerocks {
namespace bpl {

bool get_serial_number(std::string &serial_number)
{
    serial_number.assign("prplmesh12345");
    return true;
}

bool get_ruid_chipset_vendor(const sMacAddr &ruid, std::string &chipset_vendor)
{
    chipset_vendor = "prplmesh";
    return true;
}

} // namespace bpl
} // namespace beerocks
