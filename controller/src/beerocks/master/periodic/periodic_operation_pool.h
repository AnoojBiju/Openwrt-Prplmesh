/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PERIODIC_OPERATION_POOL_H_
#define _PERIODIC_OPERATION_POOL_H_

#include "periodic_operation.h"

namespace son {

class periodic_operation_pool {

public:
    periodic_operation_pool() {}
    ~periodic_operation_pool() {}

    bool add_operation(std::shared_ptr<periodic_operation> new_operation);
    bool is_operation_alive(int id);
    void kill_operation(int id);
    void pending_operation_ended(int operation_id);
    void run_operations();

private:
    std::unordered_map<int, std::shared_ptr<periodic_operation>> periodic_operations;
};

} // namespace son

#endif
