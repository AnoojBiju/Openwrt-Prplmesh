/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "task_pool.h"
#include <algorithm>

using namespace beerocks;

bool TaskPool::add_task_no_events(const std::shared_ptr<Task> &new_task)
{
    if (!new_task) {
        LOG(ERROR) << "new task pointer is nullptr";
        return false;
    }
    m_task_pool[new_task->get_task_type()] = new_task;
    return true;
}

void TaskPool::add_task(const std::shared_ptr<Task> new_task, std::vector<eTaskEvent> events)
{
    // escape
    LOG_IF(!new_task, FATAL);

    // insert into event-to-task map
    std::transform(events.begin(), events.end(),
                   std::inserter(m_event_to_tasks_map, m_event_to_tasks_map.begin()),
                   [new_task](const eTaskEvent &event) { return std::make_pair(event, new_task); });

    // insert into regular list
    add_task_no_events(new_task);
}

void TaskPool::run_tasks()
{
    // First, empty the queue of messages
    // by sending each one of them to the task that is registered
    // Note: tasks may _add_ more events to the queue in their handle_event().
    // calling handle_event() that itslef send_event() may potentially end
    // with never emptied queue: empty and filling it forever.
    // However, we don't expect such behavior of the system.
    // Possible solution if we encounter this:
    // * work with two queues: one to push to and the
    // second to pop from. Each cycle switch between them.
    while (!m_event_queue.empty()) {
        auto &event = m_event_queue.front();
        auto tasks  = m_event_to_tasks_map.equal_range(event.first);

        std::for_each(tasks.first, tasks.second,
                      [&event](std::pair<const eTaskEvent, std::shared_ptr<Task>> event_task) {
                          if (event_task.second) {
                              event_task.second->handle_event(static_cast<uint8_t>(event.first),
                                                              event.second.get());
                          }
                      });
        m_event_queue.pop();
    }

    // second, do the work for all tasks
    for (auto &task_element : m_task_pool) {
        auto &task = task_element.second;
        task->work();
    }
}

void TaskPool::send_event(eTaskType task_type, uint8_t event, const void *event_obj)
{
    auto task_it = m_task_pool.find(task_type);
    if (task_it == m_task_pool.end()) {
        LOG(ERROR) << "task of type " << int(task_type) << " does not exist in the task_pool";
        return;
    }

    auto &task = task_it->second;
    task->handle_event(event, event_obj);
}

void TaskPool::send_event(eTaskEvent event, std::shared_ptr<void> event_obj)
{
    m_event_queue.push(std::make_pair(event, event_obj));
}

bool TaskPool::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                           const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                           std::shared_ptr<beerocks_header> beerocks_header)
{
    for (auto &task_element : m_task_pool) {
        auto &task = task_element.second;
        if (task->handle_cmdu(cmdu_rx, iface_index, dst_mac, src_mac, fd, beerocks_header)) {
            return true;
        }
    }
    return false;
}
