/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "include/ambiorix_connection_factory.h"

#include "include/ambiorix_client_factory.h"

#include "include/ambiorix_client_impl.h"

#include <bcl/beerocks_backport.h>

namespace beerocks {
namespace wbapi {

std::unique_ptr<AmbiorixClient>
AmbiorixClientFactory::create_instance(const std::string &amxb_backend, const std::string &bus_uri)
{
    auto connection = AmbiorixConnectionFactory::create_instance(amxb_backend, bus_uri);
    return std::make_unique<AmbiorixClientImpl>(std::move(connection));
}

} // namespace wbapi
} // namespace beerocks
