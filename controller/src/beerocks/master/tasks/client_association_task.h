/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CLIENT_ASSOCIATION_TASK_H_
#define _CLIENT_ASSOCIATION_TASK_H_

#include "../db/db.h"
#include "task.h"
#include "task_pool.h"

namespace son {

class client_association_task : public task {
public:
    client_association_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_,
                            const std::string &task_name_ = std::string("client_association_task"));
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

private:
    db &m_database;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    task_pool &m_tasks;
};

} // namespace son

#endif
