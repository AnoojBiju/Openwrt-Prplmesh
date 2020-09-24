/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "periodic_operation.h"

using namespace son;

int periodic_operation::latest_id = 1;

periodic_operation::periodic_operation(int interval_sec_, std::string operation_name_)
    : interval_sec(interval_sec_), operation_name(operation_name_), id(latest_id++)
{
    m_last_work_timestamp = std::chrono::steady_clock::now();
}

periodic_operation::~periodic_operation() {}

void periodic_operation::work_needed()
{
    if (has_time_lapsed()) {
        this->work();
        m_last_work_timestamp = std::chrono::steady_clock::now();
    }
}

bool periodic_operation::has_time_lapsed()
{
    auto now          = std::chrono::steady_clock::now();
    auto interval_sec = std::chrono::seconds(this->interval_sec);
    return m_last_work_timestamp + interval_sec < now;
}

void periodic_operation::kill() { done = true; }
bool periodic_operation::is_done() { return done; }
