/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "include/ambiorix_connection_factory.h"
#include <bcl/beerocks_backport.h>

namespace beerocks {
namespace wbapi {

std::unique_ptr<AmbiorixConnection>
AmbiorixConnectionFactory::create_instance(const std::string &amxb_backend,
                                           const std::string &bus_uri)
{
    return std::make_unique<AmbiorixConnection>(amxb_backend, bus_uri);
}

} // namespace wbapi
} // namespace beerocks
