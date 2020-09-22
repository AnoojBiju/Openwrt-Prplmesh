/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "channel_selection_task.h"
#include "../backhaul_manager/backhaul_manager_thread.h"

namespace beerocks {

ChannelSelectionTask::ChannelSelectionTask(backhaul_manager &bhm_ctx,
                                           ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CHANNEL_SELECTION), m_bhm_ctx(bhm_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool ChannelSelectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
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

