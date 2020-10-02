/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "transaction.h"

namespace beerocks {
namespace nbapi {

AmbiorixImplTransaction::AmbiorixImplTransaction(amxd_object_t *_object) : object(_object) {}

bool AmbiorixImplTransaction::prepare_transaction()
{
    if (object) {
        LOG(ERROR) << "Failed to prepare transaction.";
        return false;
    }

    auto status = amxd_trans_init(&transaction);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't inititalize transaction, status: " << status;
        return false;
    }

    status = amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't set transaction attributes, status: " << status;
        return false;
    }

    status = amxd_trans_select_object(&transaction, object);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't select transaction object, status: " << status;
        return false;
    }

    return true;
}

} // namespace nbapi
} // namespace beerocks
