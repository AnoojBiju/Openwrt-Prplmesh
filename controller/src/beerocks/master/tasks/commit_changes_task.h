/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CLIENT_LOCATING_TASK_H_
#define _CLIENT_LOCATING_TASK_H_

#include "../db/db.h"
#include "task.h"
#include "task_pool.h"

namespace son {
class commit_changes_task : public task {
public:
    commit_changes_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_);

    virtual ~commit_changes_task() {}

protected:
    virtual void work() override;
    virtual void
    handle_response(std::string slave_mac,
                    std::shared_ptr<beerocks::beerocks_header> beerocks_header) override;

private:
    db &database;
    ieee1905_1::CmduMessageTx &cmdu_tx;
    task_pool &tasks;

    int starting_delay_ms = 0;

    enum states {
        START = 0,
        CHECK_FOR_CHANGES,
        COMMIT_THE_CHANGES,
        FINISH,
    };

    int state = START;
};

} // namespace son

#endif
