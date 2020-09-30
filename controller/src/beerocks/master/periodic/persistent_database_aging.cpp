/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "persistent_database_aging.h"
#include <bcl/beerocks_utils.h>

using namespace son;

persistent_database_aging_operation::persistent_database_aging_operation(
    std::chrono::seconds period_interval_sec_, db &database_, const std::string &operation_name_)
    : periodic_operation(period_interval_sec_, operation_name_), m_database(database_)
{
    m_database.assign_persistent_db_aging_operation_id(id);
    last_aging_check = std::chrono::system_clock::time_point::min();
}

void persistent_database_aging_operation::periodic_operation_function() {}
