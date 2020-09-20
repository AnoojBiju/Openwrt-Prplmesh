/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "commit_changes_task.h"

#include <easylogging++.h>

using namespace beerocks;
using namespace son;

commit_changes_task::commit_changes_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                         task_pool &tasks_, int starting_delay_ms_)
: task("commit changes task"), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_),
      starting_delay_ms(starting_delay_ms_)
{
}

void commit_changes_task::work()
{
    switch (state) {
    case START: {
        /*
      *  In this phase we 1st check to see if presistentDB is enabled, otherwise we'll finish
      *  and change phase to continue down the pipeline
      */
        LOG(DEBUG) << "persistent db enable=" << database.config.persistent_db;
        if (database.config.persistent_db) {
            TASK_LOG(DEBUG) << "persistent_db is disabled!";
            finish();
        } else {
            int prev_task_id = database.get_commit_changes_task_id();
            tasks.kill_task(prev_task_id);
            database.assign_commit_changes_task_id(id);

            state = CHECK_FOR_CHANGES;
            wait_for(starting_delay_ms);
        }
    } break;
    case CHECK_FOR_CHANGES: {
        /*
    *   In this phase we evaluate the expression to verify whether
    *   there are any pending changes that's awaiting to be commited.
    *   Otherwise, we finish the task 
    */
        TASK_LOG(DEBUG) << "commit_changes_task: state = CHECK_FOR_CHANGES";
        if (!database.get_db_changes_made()) {
            TASK_LOG(DEBUG) << "currently there's no data that's awaiting to be commited";
            finish();
        }

        state = COMMIT_THE_CHANGES;
        break;
    }
    case COMMIT_THE_CHANGES: {
        /*
    * In this phase we call the bpl_db::db_commit_changes to invoke    
    * bpl_db_uci::uci_commit_changes that'll then trigger uci_commit
    */
        TASK_LOG(DEBUG) << "commit_changes_task: state = CHECK_FOR_CHANGES";
        if (!database.commit_db_changes()) {
            TASK_LOG(ERROR) << "commit_changes_task: db_commit_changes returns false!";
        }

        database.reset_db_changes_made();

        finish();
        break;
    }
    case FINISH: {
        TASK_LOG(DEBUG) << "commit_changes_task: state = FINISH";
        finish();
    } break;
    default: {
        break;
    }
    }
}

void commit_changes_task::handle_response(std::string mac,
                                          std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_CONTROL_ARP_QUERY_RESPONSE: {
        auto response =
            beerocks_header->getClass<beerocks_message::cACTION_CONTROL_ARP_QUERY_RESPONSE>();
        if (!response) {
            TASK_LOG(ERROR) << "getClass failed for cACTION_CONTROL_ARP_QUERY_RESPONSE";
            return;
        } else {
            TASK_LOG(DEBUG) << "finish task";
            finish();
        }
        break;
    }
    default: {
        TASK_LOG(ERROR) << "Unsupported action_op:" << int(beerocks_header->action_op());
        break;
    }
    }
}
