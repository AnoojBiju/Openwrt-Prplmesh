/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "persistent_database_aging.h"
#include <bcl/beerocks_utils.h>
#include <easylogging++.h>
#define OPERATION_LOG(a) (LOG(a) << "operation " << operation_name << " id " << id << ": ")

using namespace son;

persistent_database_aging_operation::persistent_database_aging_operation(
    std::chrono::seconds period_interval_sec_, db &database_, const std::string &operation_name_)
    : periodic_operation(period_interval_sec_, operation_name_), m_database(database_)
{
    m_database.assign_persistent_db_aging_operation_id(id);
    last_aging_check = std::chrono::system_clock::time_point::min();
}

void persistent_database_aging_operation::periodic_operation_function()
{
    last_aging_check = std::chrono::system_clock::now();
    auto clients     = m_database.get_clients_with_persistent_data_configured();
    std::vector<sMacAddr> aged_clients;
    std::copy_if(
        clients.begin(), clients.end(), aged_clients.begin(), [&](const sMacAddr &client_mac) {
            const auto max_timelife_delay_sec =
                std::chrono::seconds(m_database.config.max_timelife_delay_minutes * 60);
            const auto unfriendly_device_max_timelife_delay_sec = std::chrono::seconds(
                m_database.config.unfriendly_device_max_timelife_delay_minutes * 60);
            // Client timelife delay
            // If a client has a predetermined timelife delay use that.
            // Otherwise use the Max timelife delay/unfriendly_device_max_timelife_delay_sec according
            // to the client's unfriendliness status.
            auto timelife_delay = std::chrono::duration_cast<std::chrono::seconds>(
                m_database.get_client_time_life_delay(client_mac));

            if (timelife_delay == std::chrono::seconds::zero()) {
                return false;
            } else if (timelife_delay == std::chrono::seconds(-1)) {
                timelife_delay =
                    (m_database.get_client_is_unfriendly(client_mac) == eTriStateBool::TRUE)
                        ? unfriendly_device_max_timelife_delay_sec
                        : max_timelife_delay_sec;
            }

            // Calculate client expiry due time
            auto parameters_last_edit = m_database.get_client_parameters_last_edit(client_mac);
            auto expiry_due           = parameters_last_edit + timelife_delay;
            // If the expiry due is less then the last aging check, the client is considered aged.
            return expiry_due < last_aging_check;
        });

    if (aged_clients.size() > 0) {
        OPERATION_LOG(TRACE) << "Found " << aged_clients.size()
                             << " aged clients, clearing persistent data";
    }
    for (const auto &aged_client : aged_clients) {
        m_database.clear_client_persistent_db(aged_client);
    }
}
