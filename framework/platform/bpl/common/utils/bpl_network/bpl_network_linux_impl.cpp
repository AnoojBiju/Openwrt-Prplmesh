/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2023 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_string_utils.h>

#include <dirent.h>
#include <linux/if_bridge.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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

bool bpl_network::add_iface_to_bridge(const std::string &bridge, const std::string &iface)
{
    LOG(DEBUG) << "add iface " << iface << " to bridge " << bridge;

    struct ifreq ifr;
    int err;
    unsigned long ifindex = if_nametoindex(iface.c_str());
    if (ifindex == 0) {
        LOG(ERROR) << "invalid iface index=" << ifindex << " for " << iface;
        return false;
    }

    int br_socket_fd;
    if ((br_socket_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
        LOG(ERROR) << "can't open br_socket_fd";
        return false;
    }

    string_utils::copy_string(ifr.ifr_name, bridge.c_str(), IFNAMSIZ);
#ifdef SIOCBRADDIF
    ifr.ifr_ifindex = ifindex;
    err             = ioctl(br_socket_fd, SIOCBRADDIF, &ifr);
    if (err < 0)
#endif
    {
        unsigned long args[4] = {BRCTL_ADD_IF, ifindex, 0, 0};

        ifr.ifr_data = (char *)args;
        err          = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);
    }

    close(br_socket_fd);
    return err < 0 ? false : true;
    /*
    std::string cmd;
    cmd = "brctl addif " + bridge + " " + iface;
    system(cmd.c_str());
    LOG(DEBUG) << cmd;
    return true;
    */
}

std::vector<std::string> bpl_network::get_bss_ifaces(const std::string &bss_iface,
                                                     const std::string &bridge_iface)
{
    if (bss_iface.empty()) {
        LOG(ERROR) << "bss_iface is empty!";
        return {};
    }
    if (bridge_iface.empty()) {
        LOG(ERROR) << "bridge_iface is empty!";
        return {};
    }

    auto ifaces_on_bridge = get_iface_list_from_bridge(bridge_iface);

    /**
     * Find all interfaces that their name contain the base bss name.
     * On upstream Hostapd the pattern is: "<bss_iface_name>.staN"
     * (e.g wlan0.0.sta1, wlan0.0.sta2 etc)
     * On MaxLinear platforms the pattern is: "bN_<bss_iface_name>"
     * (e.g b0_wlan0.0, b1_wlan0.0 etc).
     *
     * NOTE: If the VAP interface is wlan-long0.0, then the STA interface name will use an
     * abbreviated version b0_wlan-long0 instead of b0_wlan-long0.0.
     * It doesn't really work anyway because with that truncation, you may get conflicts between
     * wlan-long0.0 and wlan-lang0.1.
     */

    std::vector<std::string> bss_ifaces;
    for (const auto &iface : ifaces_on_bridge) {
        if (iface.find(bss_iface) != std::string::npos) {
            bss_ifaces.push_back(iface);
        }
    }
    return bss_ifaces;
}
} // namespace bpl
} // namespace beerocks
