/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "persistent_data_commit_task.h"

#include <easylogging++.h>

using namespace beerocks;
using namespace son;

persistent_data_commit_task::persistent_data_commit_task(db &database,
                                                         ieee1905_1::CmduMessageTx &cmdu_tx,
                                                         task_pool &tasks,
                                                         unsigned int &interval_ms)
    : task("persistent data commit task"), m_database(database), m_cmdu_tx(cmdu_tx), m_tasks(tasks),
m_interval_ms(interval_ms))
{
}

void persistent_data_commit_task::work()
{
    switch (m_state) {
    case START: {
        TASK_LOG(DEBUG) << "state = START, delayed by "
                        << m_interval_ms;

        m_state = CHECK_FOR_CHANGES;
        wait_for(m_interval_ms);
        break;
    }
    case CHECK_FOR_CHANGES: {
   /*
    *   Are there any pending changes that's awaiting to be commited?
    *   otherwise we'll revert to the previous step.
    */
        TASK_LOG(DEBUG) << "state = CHECK_FOR_CHANGES";
        if (!m_database.get_db_changes_made()) {
            TASK_LOG(DEBUG) << "currently there's no data that's awaiting to be commited";
            m_state = START;
            break;
        }

        m_state = COMMIT_THE_CHANGES;
        break;
    }
    case COMMIT_THE_CHANGES: {
        TASK_LOG(DEBUG) << "state = COMMIT_THE_CHANGES";

        if (!m_database.commit_db_changes()) {
            TASK_LOG(ERROR) << "db_commit_changes returns false!";
        } else {
            m_database.reset_db_changes_made();
            TASK_LOG(DEBUG)
                << "commiting instruction was sent succesfully";
        }

        m_state = START;
        break;
    }
    default: {
        break;
    }
    }
}
