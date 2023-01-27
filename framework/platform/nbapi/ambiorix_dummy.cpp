/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "ambiorix_dummy.h"

namespace beerocks {
namespace nbapi {

std::unique_ptr<Ambiorix::SingleObjectTransaction>
AmbiorixDummy::start_transaction(const std::string &relative_path, bool new_instance)
{
    return {};
}

std::string AmbiorixDummy::commit_transaction(std::unique_ptr<SingleObjectTransaction> trans)
{
    return {};
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
