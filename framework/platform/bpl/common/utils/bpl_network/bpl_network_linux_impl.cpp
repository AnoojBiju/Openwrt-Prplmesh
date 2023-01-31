/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2023 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <dirent.h>
#include <string.h>

#include <easylogging++.h>

#include "bpl_network.h"

namespace beerocks {
namespace bpl {

std::vector<std::string> bpl_network::get_iface_list_from_bridge(const std::string &bridge)
{
    std::vector<std::string> ifs;

    std::string path = "/sys/class/net/" + bridge + "/brif";

    DIR *d;
    struct dirent *dir;
    d = opendir(path.c_str());
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            std::string ifname = dir->d_name;
            if (ifname == "." || ifname == "..") {
                continue;
            }
            ifs.push_back(ifname);
        }
        closedir(d);
    }

    return ifs;
}
} // namespace bpl
} // namespace beerocks
