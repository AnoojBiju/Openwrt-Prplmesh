/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "persistent_commit_data_operation.h"

#include <easylogging++.h>

using namespace beerocks;
using namespace son;

persistent_commit_data_operation::persistent_commit_data_operation(
    db &database, std::chrono::seconds period_interval_sec_, const std::string &operation_name_)
    : periodic_operation(period_interval_sec_, "persistent commit data operation"),
      m_database(database)
{
}

void persistent_commit_data_operation::periodic_operation_function()
{
    OPERATION_LOG(DEBUG) << "periodic_operation_function was invoked";

    if (!m_database.get_db_changes_made()) {
        OPERATION_LOG(DEBUG) << "currently there's no data that's awaiting to be commited";
        return;
    }
    if (!m_database.commit_db_changes()) {
        OPERATION_LOG(ERROR) << "db_commit_changes returns false!";
        return;
    }

    OPERATION_LOG(DEBUG) << "periodic_operation_function has completed a cycle";
}
