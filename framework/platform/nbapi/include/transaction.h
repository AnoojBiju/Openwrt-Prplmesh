/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "ambiorix_impl.h"

namespace beerocks {
namespace nbapi {

class Transaction {
public:
    virtual bool prepare_transaction() = 0;
};

class AmbiorixImplTransaction : public Transaction {
public:
    amxd_trans_t transaction;
    amxd_object_t *object;
    AmbiorixImplTransaction(amxd_object_t *);
    virtual ~AmbiorixImplTransaction();

    /**
     * @brief Prepare transaction to the ubus
     *
     * @param relative_path Path to the object in datamodel (ex: "Controller.Network.ID").
     * @return Pointer on the object on success and nullptr otherwise.
     */
    virtual bool prepare_transaction();
};

class AmbiorixDummyTransaction : public Transaction {
    virtual bool prepare_transaction() { return; };
};

} // namespace nbapi
} // namespace beerocks

#endif
