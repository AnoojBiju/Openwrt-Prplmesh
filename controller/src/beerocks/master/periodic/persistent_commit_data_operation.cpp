/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "persistent_commit_data_operation.h"
#include <easylogging++.h>
#define OPERATION_LOG(a) (LOG(a) << "operation " << operation_name << " id " << id << ": ")

using namespace son;

persistent_commit_data_operation::persistent_commit_data_operation(
    db &database, std::chrono::seconds period_interval_sec_, const std::string &operation_name_)
    : periodic_operation(period_interval_sec_, "persistent commit data operation"),
      m_database(database)
{
    m_database.assign_persistent_db_aging_operation_id(id);
    last_data_commit_check = std::chrono::system_clock::time_point::min();
}

void persistent_commit_data_operation::periodic_operation_function()
{
    last_data_commit_check = std::chrono::system_clock::now();
    OPERATION_LOG(TRACE) << "periodic commit operation started";

    if (!m_database.is_commit_to_persistent_db_required()) {
        OPERATION_LOG(WARNING) << "No changes to persistent DB, commit is not required";
        return;
    }
    if (!m_database.commit_persistent_db_changes()) {
        OPERATION_LOG(ERROR) << "Failed to commit changes to persistent DB";
        return;
    }

    OPERATION_LOG(TRACE) << "Successfully committed changes to the persistent DB";
}
