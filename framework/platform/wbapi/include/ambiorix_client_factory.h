/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CLIENT_FACTORY_H_
#define AMBIORIX_CLIENT_FACTORY_H_

#include "ambiorix_client.h"
#include <memory>

#ifndef AMBIORIX_WBAPI_BACKEND_PATH
#define AMBIORIX_WBAPI_BACKEND_PATH "/usr/bin/mods/amxb/mod-amxb-ubus.so"
#endif
#ifndef AMBIORIX_WBAPI_BUS_URI
#define AMBIORIX_WBAPI_BUS_URI "ubus:/var/run/ubus.sock"
#endif

namespace beerocks {
namespace wbapi {

class AmbiorixClientFactory {
public:
    static std::unique_ptr<AmbiorixClient>
    create_instance(const std::string &amxb_backend = {AMBIORIX_WBAPI_BACKEND_PATH},
                    const std::string &bus_uri      = {AMBIORIX_WBAPI_BUS_URI});
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_CLIENT_FACTORY_H_ */
