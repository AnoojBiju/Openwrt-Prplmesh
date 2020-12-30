/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "shared_memory_get_latest_mid_operation.h"
#include <easylogging++.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/mman.h>

#define OPERATION_LOG(a) (LOG(a) << "operation " << operation_name << " id " << id << ": ")

using namespace son;

shared_memory_get_latest_mid_operation::shared_memory_get_latest_mid_operation(
    db &database, std::chrono::seconds period_interval_sec_, const std::string &operation_name_)
    : periodic_operation(period_interval_sec_, "persistent data commit operation"),
      m_database(database)
{
    m_database.assign_shared_memory_get_latest_mid_operation_id(id);
}

void shared_memory_get_latest_mid_operation::periodic_operation_function()
{
    // Get latest message type
    ieee1905_1::eMessageType latest = m_database.get_latest_message_type();

    // Obtain RID if possible
    int shm;
    sem_t * mutex;

    if ((mutex = sem_open("SHM_MID", NULL, 0644, 1)) == SEM_FAILED) {
        return;
    }

    sem_wait(mutex);
    OPERATION_LOG(TRACE) << "shared memory semaphore was captured by controller";
  
    sem_post(mutex);

    int res = 0;

  /*	
     int res = 0;

    // mmap cleanup
	res = munmap(shm, sizeof(int));
	if (res == -1)
	{
		perror("munmap");
		return 40;
	}

	// shm_open cleanup
	fd = shm_unlink(STORAGE_ID);
	if (fd == -1)
	{
		perror("unlink");
		return 100;
	}
    */
}
