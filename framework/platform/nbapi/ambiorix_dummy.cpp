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

AmbiorixDummy::AmbiorixDummy() {}

AmbiorixDummy::~AmbiorixDummy() {}

bool AmbiorixDummy::set(const std::string &relative_path, const std::string &value) { return true; }
bool AmbiorixDummy::set(const std::string &relative_path, const int32_t &value) { return true; }
bool AmbiorixDummy::set(const std::string &relative_path, const int64_t &value) { return true; }
bool AmbiorixDummy::set(const std::string &relative_path, const uint32_t &value) { return true; }
bool AmbiorixDummy::set(const std::string &relative_path, const uint64_t &value) { return true; }
bool AmbiorixDummy::set(const std::string &relative_path, const bool &value) { return true; }
bool AmbiorixDummy::set(const std::string &relative_path, const double &value) { return true; }
bool AmbiorixDummy::add_instance(const std::string &relative_path) { return true; }
bool AmbiorixDummy::apply_transaction() { return true; }
bool AmbiorixDummy::prepare_transaction() { return true; }
void AmbiorixDummy::stop() {}
bool AmbiorixDummy::remove_instance(const std::string &relative_path, uint32_t index)
{
    return true;
}

} // namespace nbapi
} // namespace beerocks
