/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "ambiorix_dummy.h"
#include <bcl/beerocks_backport.h>

#include <memory>

namespace beerocks {
namespace nbapi {
namespace {
namespace priv {
class Transaction : public Ambiorix::SingleObjectTransaction {
public:
    std::string relative_path;

#define TRANS_SET(TYPE)                                                                            \
    bool set(const std::string &, const TYPE &) override                                           \
    {                                                                                              \
        return true;                                                                               \
    }

    TRANS_SET(int8_t)
    TRANS_SET(int16_t)
    TRANS_SET(int32_t)
    TRANS_SET(int64_t)
    TRANS_SET(uint8_t)
    TRANS_SET(uint16_t)
    TRANS_SET(uint32_t)
    TRANS_SET(uint64_t)
    TRANS_SET(bool)
    TRANS_SET(double)
    TRANS_SET(std::string)
    TRANS_SET(sMacAddr)
#undef TRANS_SET

    bool set_time(const std::string &) override { return true; }
    bool set_current_time(const std::string &) override { return true; }
};
} // namespace priv
} // namespace

std::unique_ptr<Ambiorix::SingleObjectTransaction>
AmbiorixDummy::begin_transaction(const std::string &relative_path, bool new_instance)
{
    if (new_instance) {
        return {};
    }

    auto ret = std::make_unique<priv::Transaction>();
    ret->relative_path = relative_path;

    return ret;
}
std::string AmbiorixDummy::commit_transaction(std::unique_ptr<SingleObjectTransaction> trans)
{
    auto derived = static_cast<priv::Transaction*>(trans.get());
    return std::move(derived->relative_path);
}
bool AmbiorixDummy::remove_instance(const std::string &relative_path, uint32_t index)
{
    return true;
}
uint32_t AmbiorixDummy::get_instance_index(const std::string &specific_path, const std::string &key)
{
    // Return false (0) because method can be used for checking instance present in Data Model or not
    return 0;
}
std::string AmbiorixDummy::get_datamodel_time_format() { return {}; }

bool AmbiorixDummy::remove_all_instances(const std::string &relative_path) { return true; }

bool AmbiorixDummy::add_optional_subobject(const std::string &path_to_obj,
                                           const std::string &subobject_name)
{
    return true;
}

bool AmbiorixDummy::remove_optional_subobject(const std::string &path_to_obj,
                                              const std::string &subobject_name)
{
    return true;
}

bool AmbiorixDummy::read_param(const std::string &obj_path, const std::string &param_name,
                               uint64_t *param_val)
{
    return true;
}

bool AmbiorixDummy::read_param(const std::string &obj_path, const std::string &param_name,
                               std::string *param_val)
{
    return true;
}

} // namespace nbapi
} // namespace beerocks
