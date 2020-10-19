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
    bool set(const std::string &relative_path, const std::string &parameter,
             const std::string &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int32_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const int64_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint32_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const uint64_t &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const bool &value) override;
    bool set(const std::string &relative_path, const std::string &parameter,
             const double &value) override;
    uint32_t add_instance(const std::string &relative_path) override;
    bool remove_instance(const std::string &relative_path, uint32_t index) override;
    uint32_t get_instance_index(const std::string &specific_path, const std::string &key) override;
    std::string get_datamodel_time_format() override;
    bool remove_all_instances(const std::string &relative_path) override;
};

} // namespace nbapi
} // namespace beerocks

#endif
