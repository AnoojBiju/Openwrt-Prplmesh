/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CONNECTION_FACTORY_H_
#define AMBIORIX_CONNECTION_FACTORY_H_

#include "ambiorix_connection.h"
#include <memory>

namespace beerocks {
namespace wbapi {

/**
 * @class AmbiorixConnectionFactory
 */
class AmbiorixConnectionFactory {
public:
    static std::unique_ptr<AmbiorixConnection> create_instance(const std::string &amxb_backend,
                                                               const std::string &bus_uri);
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_CONNECTION_FACTORY_H_ */
