/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "periodic_operation_pool.h"

#include <easylogging++.h>

using namespace son;

bool periodic_operation_pool::add_operation(std::shared_ptr<periodic_operation> new_operation)
{
    LOG(TRACE) << "inserting new operation, id=" << int(new_operation->id)
               << " operation name=" << new_operation->operation_name;
    return (periodic_operations.insert(std::make_pair(new_operation->id, new_operation))).second;
}

bool periodic_operation_pool::is_operation_done(int id)
{
    auto it = periodic_operations.find(id);
    if (it != periodic_operations.end() && it->second != nullptr && it->second->is_done()) {
        return true;
    }
    return false;
}

bool periodic_operation_pool::is_operation_pending(int id)
{
    auto it = periodic_operations.find(id);
    if (it != periodic_operations.end() && it->second != nullptr && !it->second->is_done()) {
        return true;
    }
    return false;
}

void periodic_operation_pool::kill_operation(int id)
{
    auto it = periodic_operations.find(id);
    if (it != periodic_operations.end() && it->second != nullptr) {
        LOG(DEBUG) << "killing operation " << it->second->operation_name << ", id " << it->first;
        it->second->kill();
    }
}

void periodic_operation_pool::run_operations()
{
    for (auto it = periodic_operations.begin(); it != periodic_operations.end();) {
        it->second->work_needed();
        if (it->second->is_done()) {
            LOG(DEBUG) << "erasing task " << it->second->operation_name << ", id " << it->first;
            it = periodic_operations.erase(it);
        } else {
            ++it;
        }
    }
}
