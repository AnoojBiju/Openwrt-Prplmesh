/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "./include/ambiorix_dummy.h"
#include <fstream>

AmbiorixDummy::AmbiorixDummy() {}

AmbiorixDummy::~AmbiorixDummy() {}

bool AmbiorixDummy::init(const std::string &amxb_backend, const std::string &bus_uri,
                         const std::string &datamodel_path)
{
    size_t len;
    std::ifstream file;

    len = amxb_backend.length();
    file.open(amxb_backend);
    if (!file || len < 4 || amxb_backend.compare(len - 3, 3, ".so") != 0) {
        std::cout << "Failed to load the ambiorix backend\n";
        file.close();
        return false;
    }
    file.close();
    len = bus_uri.length();
    if (len < 6 || bus_uri.compare(len - 5, 5, ".sock") != 0) {
        std::cout << "Failed to connect to the bus\n";
        return false;
    }
    len = datamodel_path.length();
    file.open(datamodel_path);
    if (!file || len < 5 || datamodel_path.compare(len - 4, 4, ".odl") != 0) {
        std::cout << "Failed to load the ODL data model \n";
        file.close();
        return false;
    }
    file.close();
    return true;
}

bool AmbiorixDummy::set(const std::string &relative_path, const std::string &value) { return true; }

bool AmbiorixDummy::set(const std::string &relative_path, const int32_t &value) { return true; }

bool AmbiorixDummy::set(const std::string &relative_path, const int64_t &value) { return true; }

bool AmbiorixDummy::set(const std::string &relative_path, const uint32_t &value) { return true; }

bool AmbiorixDummy::set(const std::string &relative_path, const uint64_t &value) { return true; }

bool AmbiorixDummy::set(const std::string &relative_path, const bool &value) { return true; }

bool AmbiorixDummy::set(const std::string &relative_path, const double &value) { return true; }

void AmbiorixDummy::stop() {}
