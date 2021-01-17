/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TASK_POOL_INTERFACE_H_
#define _TASK_POOL_INTERFACE_H_

#include <memory>
#include <vector>

namespace beerocks {

class Task;

/**
 * @brief All possible events in the system are defined here
 */
enum class eTaskEvent {
    CAC_STARTED_NOTIFICATION,
    CAC_COMPLETED_NOTIFICATION,
    SWITCH_CHANNEL_NOTIFICATION_EVENT,
    /* indication about the time to wait for switch channel */
    SWITCH_CHANNEL_DURATION_TIME,
    SWTICH_CHANNEL_REQUEST,
    SWITCH_CHANNEL_REPORT,
};

// helper for hashing the event type
struct TaskEventHash {
    std::size_t operator()(eTaskEvent event) const { return static_cast<std::size_t>(event); }
};

/**
 * @brief The TaskPoolInterface provides interface for adding tasks
 * and sending messages between tasks
 */
class TaskPoolInterface {
public:
    /**
     * @brief Add new task to the task pool with 
     * a list of messages this task wants to handle
     * 
     * @param new_task Shared pointer to the task.
     */
    virtual void add_task(const std::shared_ptr<Task> new_task) = 0;

    /**
     * @brief Send an event to all registered tasks
     * 
     * @param event the id of the event - unique system wide
     * @param event_obj shared pointer to some chunk of memory used to pass data to the task
     */
    virtual void send_event(eTaskEvent event, std::shared_ptr<void> event_obj = nullptr) = 0;
};

} // namespace beerocks

#endif
