/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "station.h"

namespace prplmesh {
namespace controller {
namespace db {

void Station::assign_client_locating_task_id(int new_task_id, bool new_connection)
{
    if (new_connection) {
        m_client_locating_task_id_new_connection = new_task_id;
    } else {
        m_client_locating_task_id_exist_connection = new_task_id;
    }
}

int Station::get_client_locating_task_id(bool new_connection)
{
    if (new_connection) {
        return m_client_locating_task_id_new_connection;
    }
    return m_client_locating_task_id_exist_connection;
}

} // namespace db
} // namespace controller
} // namespace prplmesh
