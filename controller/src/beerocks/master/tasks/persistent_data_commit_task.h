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
#include "task.h"
#include "task_pool.h"

#include <limits.h>

namespace son {
class persistent_data_commit_task : public task {
public:
    persistent_data_commit_task(db &database, ieee1905_1::CmduMessageTx &cmdu_tx, task_pool &tasks,
                                unsigned int& interval_ms);

    virtual ~persistent_data_commit_task() {}

protected:
    virtual void work() override;

private:
    db &m_database;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    task_pool &m_tasks;

    unsigned int m_interval_ms;

    enum states {
        START = 0,
        CHECK_FOR_CHANGES,
        COMMIT_THE_CHANGES,
        FINISH,
    } m_state = START;
};

} // namespace son

#endif
