/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "client_association_task.h"

using namespace beerocks;
using namespace net;
using namespace son;

client_association_task::client_association_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                                 task_pool &tasks_, const std::string &task_name_)
    : task(task_name_), m_database(database_), m_cmdu_tx(cmdu_tx_), m_tasks(tasks_)
{
}

bool client_association_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                                    ieee1905_1::CmduMessageRx &cmdu_rx)
{
    return false;
}
