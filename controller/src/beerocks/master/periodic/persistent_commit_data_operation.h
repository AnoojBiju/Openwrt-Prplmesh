/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PERSISTENT_DATA_COMMIT_TASK_H
#define _PERSISTENT_DATA_COMMIT_TASK_H

#include "../db/db.h"
#include "periodic_operation.h"
#include "periodic_operation_pool.h"

namespace son {
class persistent_commit_data_operation : public periodic_operation {
public:
    persistent_commit_data_operation(
        db &database, std::chrono::seconds period_interval_sec_,
        const std::string &operation_name_ = std::string("persistent commit data operation"));

    virtual ~persistent_commit_data_operation() {}

protected:
    virtual void periodic_operation_function() override;

private:
    db &m_database;
    std::chrono::system_clock::time_point last_data_commit_check;
};

} // namespace son

#endif
