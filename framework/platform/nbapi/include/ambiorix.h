/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_H
#define AMBIORIX_H

#include <iostream>

/**
 * @class Ambiorix
 * @brief Interface for AmbiorixImpl and AmbiorixDummy classes
 */
class Ambiorix {
public:
    virtual bool init(const std::string &amxb_backend, const std::string &bus_uri,
                      const std::string &datamodel_path)                         = 0;
    virtual bool set(const std::string &relative_path, const std::string &value) = 0;
    virtual bool set(const std::string &relative_path, const int32_t &value)     = 0;
    virtual bool set(const std::string &relative_path, const int64_t &value)     = 0;
    virtual bool set(const std::string &relative_path, const uint32_t &value)    = 0;
    virtual bool set(const std::string &relative_path, const uint64_t &value)    = 0;
    virtual bool set(const std::string &relative_path, const bool &value)        = 0;
    virtual bool set(const std::string &relative_path, const double &value)      = 0;
    virtual void stop()                                                          = 0;
};

#endif
