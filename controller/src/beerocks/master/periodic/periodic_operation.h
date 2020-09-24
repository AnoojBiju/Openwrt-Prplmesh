/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PERIODIC_OPERATION_H_
#define _PERIODIC_OPERATION_H_

#define OPERATION_LOG(a) (LOG(a) << "operation " << operation_name << " id " << id << ": ")

#include "../../common/include/mapf/common/err.h"
#include <chrono>
#include <easylogging++.h>

namespace son {

class periodic_operation {
public:
    periodic_operation(int period_interval_sec_, std::string operation_name_ = std::string(""));
    virtual ~periodic_operation() {}
    void work_needed();
    bool has_time_lapsed();
    virtual void work() = 0;
    void kill();
    bool is_done();

    const int id;
    std::string operation_name;

protected:
    int interval_sec;

private:
    std::chrono::steady_clock::time_point m_last_work_timestamp;
    static int latest_id;
    bool done = false;
};

} //  namespace son

#endif
