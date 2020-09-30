/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_H
#define AMBIORIX_H

#include <easylogging++.h>
#include <mapf/common/utils.h>

namespace beerocks {
namespace nbapi {

typedef struct _amxd_transaction amxd_trans_t;
typedef struct _amxd_object {
    bool init_me;
} amxd_object_t;

/**
 * @class Ambiorix
 * @brief Interface for AmbiorixImpl and AmbiorixDummy classes
 */
class Ambiorix {
public:
    virtual bool set(const std::string &relative_path, const std::string &value)   = 0;
    virtual bool set(const std::string &relative_path, const int32_t &value)       = 0;
    virtual bool set(const std::string &relative_path, const int64_t &value)       = 0;
    virtual bool set(const std::string &relative_path, const uint32_t &value)      = 0;
    virtual bool set(const std::string &relative_path, const uint64_t &value)      = 0;
    virtual bool set(const std::string &relative_path, const bool &value)          = 0;
    virtual bool set(const std::string &relative_path, const double &value)        = 0;
    virtual bool add_instance(const std::string &relative_path)                    = 0;
    virtual bool remove_instance(const std::string &relative_path, uint32_t index) = 0;
    virtual void stop()                                                            = 0;
    virtual bool apply_transaction(amxd_trans_t &transaction)                      = 0;
    virtual amxd_object_t *prepare_transaction(const std::string &relative_path,
                                               amxd_trans_t &transaction)          = 0;
};

} // namespace nbapi
} // namespace beerocks

#endif
