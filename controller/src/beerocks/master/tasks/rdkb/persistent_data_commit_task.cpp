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

persistent_data_commit_task::persistent_data_commit_task(db &database, ieee1905_1::CmduMessageTx &cmdu_tx,
                                         task_pool &tasks, unsigned int starting_delay_ms)
    : task("persistent data commit task"), m_database(database), m_cmdu_tx(cmdu_tx), m_tasks(tasks),
      m_starting_delay_ms(starting_delay_ms)
{
    this->set_task_timeout(std::numeric_limits<int>::max());
}

void persistent_data_commit_task::work()
{
    switch (m_state) {
    case INIT: {
        TASK_LOG(DEBUG) << "persistent_data_commit_task: state = init";

        LOG(DEBUG) << "persistent db enable=" << m_database.config.persistent_db;

        if (!m_database.config.persistent_db) {
            TASK_LOG(DEBUG) << "persistent_db is disabled!";
            finish();
            break;
        }

        m_state = START;
        break;
    }
    case START: {
        TASK_LOG(DEBUG) << "persistent_data_commit_task: state = START, delayed by "
        << m_starting_delay_ms;

        m_state = CHECK_FOR_CHANGES;
        wait_for(m_starting_delay_ms);
        break;
    }
    case CHECK_FOR_CHANGES: {
    /*
    *   Are there any pending changes that's awaiting to be commited?
    *   otherwise we'll revert to the previous step.
    */
        TASK_LOG(DEBUG) << "persistent_data_commit_task: state = CHECK_FOR_CHANGES";
        if (!m_database.get_db_changes_made()) {
            TASK_LOG(DEBUG) << "currently there's no data that's awaiting to be commited";
            m_state = START;
            break;
        }

        m_state = COMMIT_THE_CHANGES;
        break;
    }
    case COMMIT_THE_CHANGES: {
        TASK_LOG(DEBUG) << "persistent_data_commit_task: state = COMMIT_THE_CHANGES";
        
        if (!m_database.commit_db_changes()) {
            TASK_LOG(ERROR) << "persistent_data_commit_task: db_commit_changes returns false!";
        }
        else {
            m_database.reset_db_changes_made();
            TASK_LOG(DEBUG) << "persistent_data_commit_task: commiting instruction was sent succesfully";
        }

        m_state = START;
        break;
    }
    case FINISH: {
        TASK_LOG(DEBUG) << "persistent_data_commit_task: task was finished manually";
        finish();
        break;
    }
    default: {
        break;
    }
    }
}

void persistent_data_commit_task::handle_response(std::string mac,
                                          std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_CONTROL_ARP_QUERY_RESPONSE: {
        auto response =
            beerocks_header->getClass<beerocks_message::cACTION_CONTROL_ARP_QUERY_RESPONSE>();
        
        if (!response) {
            TASK_LOG(ERROR) << "getClass failed for cACTION_CONTROL_ARP_QUERY_RESPONSE";
            finish();
            break;
        }  
           
        TASK_LOG(DEBUG) << "finish task";
        finish();        
        break;
    }
    default: {
        TASK_LOG(ERROR) << "Unsupported action_op:" << int(beerocks_header->action_op());
        break;
    }
    }
}

 void persistent_data_commit_task::handle_responses_timeout(
         std::unordered_multimap<std::string, beerocks_message::eActionOp_CONTROL>
         timed_out_macs)
{
    switch (m_state) {
    default: {
        TASK_LOG(ERROR) << "Unknown state: " << int(m_state);
        break;
    }
    }
}
