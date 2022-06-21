/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef PRPLMESH_AMX_CLIENT_H
#define PRPLMESH_AMX_CLIENT_H

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxc/amxc.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

#include <amxo/amxo.h>
#include <amxo/amxo_save.h>

#include <easylogging++.h>

#include <iostream>
#include <locale.h>
#include <time.h>

namespace beerocks {
namespace prplmesh_amx {

class AmxClient {

public:
    AmxClient(){};
    AmxClient(const AmxClient &) = delete;
    AmxClient &operator=(const AmxClient &) = delete;
    ~AmxClient();

    // Connect to an ambiorix.
    bool amx_initialize(const std::string &amxb_backend, const std::string &bus_uri);

    // Get a object from bus using object_path.
    amxc_var_t *get_object(const std::string &object_path);
    const amxc_htable_t *get_htable_object(const std::string &object_path);

private:
    amxb_bus_ctx_t *bus_ctx = nullptr;
};

} // namespace prplmesh_amx
} // namespace beerocks

#endif // PRPLMESH_AMX_CLIENT_H
