/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "prplmesh_amx_client.h"
#include <chrono>

namespace beerocks {
namespace prplmesh_amx {

bool AmxClient::amx_initialize(const std::string &amxb_backend, const std::string &bus_uri)
{
    int retval = 0;

    // A bus specific backend is needed before a connection can be created
    retval = amxb_be_load(amxb_backend.c_str());
    if (retval != 0) {
        LOG(ERROR) << "Failed to load the backend :" << amxb_backend.c_str()
                   << " , retval: " << retval;
        return false;
    }

    // Create a connection to a bus, a URI is needed.
    retval = amxb_connect(&bus_ctx, bus_uri.c_str());
    if (retval != 0) {
        LOG(ERROR) << "Failed to connect to the bus " << bus_uri.c_str() << " , retval: " << retval;
        return false;
    }

    return true;
}

static constexpr int amxb_get_timeout = 3;

amxc_var_t *AmxClient::get_object(const std::string &object_path, bool &request_timed_out)
{
    amxc_var_t retval_t;
    amxc_var_init(&retval_t);

    auto start = std::chrono::steady_clock::now();
    if (amxb_get(bus_ctx, object_path.c_str(), 0, &retval_t, amxb_get_timeout) == AMXB_STATUS_OK) {
        amxc_var_t *result = amxc_var_get_first(GET_ARG(&retval_t, "0"));
        if (result && (amxc_var_type_of(result) == AMXC_VAR_ID_HTABLE)) {
            return result;
        }
    }
    auto finish       = std::chrono::steady_clock::now();
    auto elapsed      = std::chrono::duration_cast<std::chrono::seconds>(finish - start);
    request_timed_out = elapsed.count() >= amxb_get_timeout;

    amxc_var_clean(&retval_t);
    return nullptr;
}

const amxc_htable_t *AmxClient::get_htable_object(const std::string &object_path)
{
    amxc_var_t retval_t;
    amxc_var_init(&retval_t);

    if (amxb_get(bus_ctx, object_path.c_str(), 0, &retval_t, amxb_get_timeout) == AMXB_STATUS_OK) {
        const amxc_htable_t *htable_retval =
            amxc_var_constcast(amxc_htable_t, GETI_ARG(&retval_t, 0));
        return htable_retval;
    }
    amxc_var_clean(&retval_t);
    return nullptr;
}

int AmxClient::set_object(const std::string &path, amxc_var_t *value, amxc_var_t *ret)
{
    return amxb_set(bus_ctx, path.c_str(), value, ret, 3);
}

AmxClient::~AmxClient()
{
    amxb_free(&bus_ctx);
    amxb_be_remove_all();
}

} // namespace prplmesh_amx
} // namespace beerocks
