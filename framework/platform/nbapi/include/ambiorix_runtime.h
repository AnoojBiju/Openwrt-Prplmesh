/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_RT_H
#define AMBIORIX_RT_H
#include <map>
#include <string>

// Ambiorix
#include <amxb/amxb_register.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>
#include <amxrt/amxrt.h>

namespace beerocks {
namespace nbapi {
class Amxrt {
private:
public:
    static int index;
    Amxrt() { amxrt_new(); }
    ~Amxrt()
    {
        amxrt_stop();
        amxrt_delete();
    }
    static void Initialize(int argc, char *argv[], amxrt_arg_fn_t handler)
    {
        index = 0;
        amxrt_config_init(argc, argv, &index, handler);
        // Add error handling if needed
    }

    static void LoadOdlFiles(int argc, char *argv[])
    {
        amxrt_load_odl_files(argc, argv, index);
        // Add error handling if needed
    }

    static void AddAutoSave(amxo_entry_point_t callback)
    {
        amxo_parser_add_entry_point(amxrt_get_parser(), callback);
    }

    static void Connect()
    {
        amxrt_connect();
        // Add error handling if needed
    }

    static void EnableSyssigs()
    {
        amxc_var_t *config  = amxrt_get_config();
        amxc_var_t *syssigs = GET_ARG(config, "system-signals");
        if (syssigs != NULL) {
            amxrt_enable_syssigs(syssigs);
        }
    }

    static void CreateEventLoop()
    {
        amxrt_el_create();
        // Add error handling if needed
    }

    static int RegisterOrWait()
    {
        return amxrt_register_or_wait();
        // Add error handling if needed
    }

    static void RunEventLoop() { amxrt_el_start(); }

    static amxd_dm_t *getDatamodel() { return amxrt_get_dm(); }
    static amxo_parser_t *getParser() { return amxrt_get_parser(); }
    static amxc_var_t *getConfig() { return amxrt_get_config(); }
};
} // namespace nbapi
} // namespace beerocks
#endif
