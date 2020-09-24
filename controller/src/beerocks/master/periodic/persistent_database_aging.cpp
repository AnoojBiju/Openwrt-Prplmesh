/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "persistent_database_aging.h"
#include <bcl/beerocks_utils.h>

using namespace son;

persistent_database_aging_operation::persistent_database_aging_operation(
    int period_interval_sec_, db &database_, std::string operation_name_)
    : periodic_operation(period_interval_sec_, operation_name_), database(database_)
{
    last_aging_check = std::chrono::system_clock::time_point::min();
}

void persistent_database_aging_operation::work()
{
    last_aging_check              = std::chrono::system_clock::now();
    auto clients_                 = database.get_clients_with_persistent_data_configured();
    std::vector<sMacAddr> clients = {clients_.begin(), clients_.end()};
    auto aged_clients =
        beerocks::utils::vector_filter<sMacAddr>(clients, [&](const sMacAddr &client_mac) {
            const auto max_timelife_delay_sec =
                std::chrono::seconds(database.config.max_timelife_delay_days * 24 * 3600);
            const auto unfriendly_device_max_timelife_delay_sec = std::chrono::seconds(
                database.config.unfriendly_device_max_timelife_delay_days * 24 * 3600);
            // Client timelife delay
            // If a client has a predetermined timelife delay use that.
            // Otherwise use the Max timelife delay.
            auto timelife_delay = database.get_client_time_life_delay(client_mac);
            if (timelife_delay == std::chrono::seconds::zero()) {
                timelife_delay = database.get_client_is_friendly(client_mac) == eTriStateBool::FALSE
                                     ? unfriendly_device_max_timelife_delay_sec
                                     : max_timelife_delay_sec;
            }

            // Calculate client expiry due time
            auto parameters_last_edit = database.get_client_parameters_last_edit(client_mac);
            auto expiry_due           = parameters_last_edit + timelife_delay;
            // If the expiry due is less then the last aging check, the client is considered aged.
            return expiry_due < last_aging_check;
        });

    if (aged_clients.size() > 0) {
        OPERATION_LOG(TRACE) << "Found " << aged_clients.size()
                             << " aged clients, clearing persistent data";
    }
    for (const auto &aged_client : aged_clients) {
        database.clear_client_persistent_db(aged_client);
    }
}
