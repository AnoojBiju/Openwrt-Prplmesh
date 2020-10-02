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

/**
 * @class Ambiorix
 * @brief Dummy version of Ambiorix class
 */
class AmbiorixDummy : public Ambiorix {
public:
    AmbiorixDummy();
    virtual ~AmbiorixDummy();
    virtual bool set(const std::string &relative_path, const std::string &value);
    virtual bool set(const std::string &relative_path, const int32_t &value);
    virtual bool set(const std::string &relative_path, const int64_t &value);
    virtual bool set(const std::string &relative_path, const uint32_t &value);
    virtual bool set(const std::string &relative_path, const uint64_t &value);
    virtual bool set(const std::string &relative_path, const bool &value);
    virtual bool set(const std::string &relative_path, const double &value);
    virtual bool add_instance(const std::string &relative_path);
    virtual bool remove_instance(const std::string &relative_path, uint32_t index);
    virtual void stop();
    virtual bool apply_transaction();
    virtual bool prepare_transaction();
};

} // namespace nbapi
} // namespace beerocks

#endif
