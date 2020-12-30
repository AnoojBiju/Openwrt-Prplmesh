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
class shared_memory_get_latest_mid_operation : public periodic_operation {
public:
    shared_memory_get_latest_mid_operation(
        db &database, std::chrono::seconds period_interval_sec_,
        const std::string &operation_name_ = std::string("shared memory get latest mid operation"));

    virtual ~shared_memory_get_latest_mid_operation() {}

protected:
    virtual void periodic_operation_function() override;

private:
    db &m_database;
};

} // namespace son

#endif
