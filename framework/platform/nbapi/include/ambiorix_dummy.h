/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_DUMMY_H
#define AMBIORIX_DUMMY_H

#include "ambiorix.h"

namespace beerocks {
namespace nbapi {

class AmbiorixDummyTransaction : public Transaction {
    virtual void start_transaction() { return; };
};

/**
 * @class Ambiorix
 * @brief Dummy version of Ambiorix class
 */
class AmbiorixDummy : public Ambiorix {
public:
    AmbiorixDummy();
    virtual ~AmbiorixDummy();
    bool set(const std::string &relative_path, const std::string &value) override;
    bool set(const std::string &relative_path, const int32_t &value) override;
    bool set(const std::string &relative_path, const int64_t &value) override;
    bool set(const std::string &relative_path, const uint32_t &value) override;
    bool set(const std::string &relative_path, const uint64_t &value) override;
    bool set(const std::string &relative_path, const bool &value) override;
    bool set(const std::string &relative_path, const double &value) override;
    bool add_instance(const std::string &relative_path) override;
    bool remove_instance(const std::string &relative_path, uint32_t index) override;
    void stop() override;
    bool apply_transaction(Transaction *transaction) override;
};

} // namespace nbapi
} // namespace beerocks

#endif
