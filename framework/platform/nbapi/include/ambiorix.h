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

/**
 * @class Ambiorix
 * @brief Interface for AmbiorixImpl and AmbiorixDummy classes
 */
class Ambiorix {
public:
    Ambiorix(){};
    Ambiorix(const Ambiorix &) = delete;
    Ambiorix &operator=(const Ambiorix &)                                          = delete;
    virtual ~Ambiorix()                                                            = 0;
    virtual bool set(const std::string &relative_path, const std::string &value)   = 0;
    virtual bool set(const std::string &relative_path, const int32_t &value)       = 0;
    virtual bool set(const std::string &relative_path, const int64_t &value)       = 0;
    virtual bool set(const std::string &relative_path, const uint32_t &value)      = 0;
    virtual bool set(const std::string &relative_path, const uint64_t &value)      = 0;
    virtual bool set(const std::string &relative_path, const bool &value)          = 0;
    virtual bool set(const std::string &relative_path, const double &value)        = 0;
    virtual uint32_t add_instance(const std::string &relative_path)                = 0;
    virtual bool remove_instance(const std::string &relative_path, uint32_t index) = 0;
    virtual int get_instance_index(const std::string &relative_path, const std::string &key) = 0;
};

inline Ambiorix::~Ambiorix() {}

} // namespace nbapi
} // namespace beerocks

#endif
