/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include <bcl/beerocks_event_loop.h>
#include <easylogging++.h>

#include "ambiorix_client.h"
#include "wbapi_utils.h"

#include "../src/beerocks/master/db/db.h"
#include "../src/beerocks/master/son_actions.h"

namespace prplmesh {
namespace controller {
namespace whm {

class WifiManager {
public:
    WifiManager(std::shared_ptr<beerocks::EventLoop> event_loop, son::db *master_db);

    ~WifiManager();

    void subscribe_to_bss_info_config_change();

private:
    bool bss_info_config_change();
    std::unique_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl;
    son::db *m_ctx_wifi_db;
    std::shared_ptr<beerocks::EventLoop> m_event_loop;
};

} // namespace whm
} // namespace controller
} // namespace prplmesh
#endif // WIFI_MANAGER_H
