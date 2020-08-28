/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "link_metrics_collection_task.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

namespace beerocks {

LinkMetricsCollectionTask::LinkMetricsCollectionTask(backhaul_manager &btl_ctx,
                                                     ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::LINK_METRICS_COLLECTION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool LinkMetricsCollectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                            const sMacAddr &src_mac,
                                            std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

} // namespace beerocks
