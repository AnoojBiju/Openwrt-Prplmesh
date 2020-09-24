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
#include <iostream>

/**
 * @class Ambiorix
 * @brief Dummy version of Ambiorix class
 */
class AmbiorixDummy : public Ambiorix {
public:
    AmbiorixDummy();
    ~AmbiorixDummy();
    bool init(const std::string &amxb_backend, const std::string &bus_uri,
              const std::string &datamodel_path) override;
    virtual bool set(const std::string &relative_path, const std::string &value) override;
    virtual bool set(const std::string &relative_path, const int32_t &value) override;
    virtual bool set(const std::string &relative_path, const int64_t &value) override;
    virtual bool set(const std::string &relative_path, const uint32_t &value) override;
    virtual bool set(const std::string &relative_path, const uint64_t &value) override;
    virtual bool set(const std::string &relative_path, const bool &value) override;
    virtual bool set(const std::string &relative_path, const double &value) override;
    virtual void stop() override;
};

#endif
