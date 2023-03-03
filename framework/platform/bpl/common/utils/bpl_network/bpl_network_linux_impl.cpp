/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2023 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl_network/bpl_network.h>

#include <bcl/beerocks_string_utils.h>

#include <dirent.h>
#include <limits.h>
#include <linux/if_bridge.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <easylogging++.h>

using namespace beerocks::net;
namespace beerocks {
namespace bpl {

#define NL_BUFSIZE 8192

struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

static int readNlSock(int fd, char *msg, uint32_t seq, uint32_t pid)
{
    int nl_msg_len = 0;

    for (;;) {

        // Read Netlink message
        auto ret = recv(fd, msg, NL_BUFSIZE - nl_msg_len, 0);

        if (ret == 0) {
            LOG(WARNING) << "netlink connection closed: recv returned 0";
            return -1;
        } else if (ret < 0) {
            LOG(ERROR) << "Failed reading netlink socket: " << strerror(errno);
            return -1;
        }

        // Netlink header
        auto header = (struct nlmsghdr *)msg;

        // Validate the header
        if (ret < int(sizeof(struct nlmsghdr)) || ret < int(header->nlmsg_len) ||
            header->nlmsg_len < sizeof(struct nlmsghdr)) {
            LOG(WARNING) << "Invalid netlink message header - msg len = " << int(header->nlmsg_len)
                         << " (" << int(ret) << ")";
            return -1;
        }

        if (header->nlmsg_type == NLMSG_ERROR) {
            LOG(WARNING) << "Read netlink error message";
            return -1;
        }

        // Not the last message
        if (header->nlmsg_type != NLMSG_DONE) {
            msg += ret;
            nl_msg_len += ret;
        } else {
            break;
        }

        // Multipart of someother message
        if (((header->nlmsg_flags & NLM_F_MULTI) == 0) || (header->nlmsg_seq != seq) ||
            (header->nlmsg_pid != pid)) {
            break;
        }
    }

    // Return the length of the read message
    return nl_msg_len;
}

/* For parsing the route info returned */
static int parseRoutes(struct nlmsghdr *nlHdr, std::shared_ptr<route_info> rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    // If the route is not for AF_INET then return
    if (rtMsg->rtm_family != AF_INET)
        return (0);

    // get the rtattr field
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen  = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF: {
            auto index            = *(int *)RTA_DATA(rtAttr);
            auto iface_index_name = network_utils::linux_get_iface_name(index);
            std::copy_n(iface_index_name.begin(), iface_index_name.length(), rtInfo->ifName);
            break;
        }
        case RTA_GATEWAY:
            rtInfo->gateWay.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        default:
            break;
        }
    }

    if ((rtInfo->dstAddr.s_addr == 0) && (rtInfo->gateWay.s_addr != 0)) {
        return (1);
    }
    if (rtInfo->dstAddr.s_addr == rtInfo->srcAddr.s_addr) {
        return (2);
    }
    return (0);
}

static std::vector<network_utils::ip_info> get_ip_list()
{
    std::vector<network_utils::ip_info> ip_list;
    struct nlmsghdr *nlMsg;
    struct ifreq ifr;
    char *msgBuf = NULL;

    int sock, fd, len;
    uint32_t msgSeq = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG(ERROR) << "Can't open SOCK_DGRAM socket";
        return ip_list;
    }

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        LOG(ERROR) << "Can't open netlink socket";
        close(fd);
        return ip_list;
    }

    msgBuf = new char[NL_BUFSIZE];
    memset(msgBuf, 0, NL_BUFSIZE);

    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *)msgBuf;

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len  = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq   = msgSeq++;                   // Sequence of the message packet.
    nlMsg->nlmsg_pid   = (uint32_t)getpid();         // PID of process sending the request.

    /* Send the request */
    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        LOG(ERROR) << "send()";
        delete[] msgBuf;
        close(sock);
        close(fd);
        return ip_list;
    }

    /* Read the response */
    if ((len = readNlSock(sock, msgBuf, msgSeq, nlMsg->nlmsg_pid)) < 0) {
        LOG(ERROR) << "readNlSock()";
        delete[] msgBuf;
        close(sock);
        close(fd);
        return ip_list;
    }

    /* Parse and print the response */
    uint32_t ip_uint;
    net::network_utils::ip_info gw_ip_info;
    auto rtInfo = std::make_shared<route_info>();
    if (!rtInfo) {
        delete[] msgBuf;
        close(sock);
        close(fd);
        LOG(ERROR) << "rtInfo allocation failed!";
        return std::vector<network_utils::ip_info>();
    }
    for (; NLMSG_OK(nlMsg, uint32_t(len)); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        memset(rtInfo.get(), 0, sizeof(struct route_info));
        int rtInfo_ret = parseRoutes(nlMsg, rtInfo);
        if (rtInfo_ret == 1) { // GW address
            gw_ip_info.gw    = network_utils::ipv4_to_string(rtInfo->gateWay.s_addr);
            gw_ip_info.iface = std::string(rtInfo->ifName);
            LOG(DEBUG) << "gw=" << gw_ip_info.gw << " iface=" << gw_ip_info.iface;
        } else if (rtInfo_ret == 2) { // Iface /IP addr
            network_utils::ip_info ip_info;

            ip_info.iface = std::string(rtInfo->ifName);

            ifr.ifr_addr.sa_family = AF_INET;
            string_utils::copy_string(ifr.ifr_name, rtInfo->ifName, IFNAMSIZ);

            if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
                continue; // skip, if can't read ip
            }
            ip_uint           = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
            ip_info.ip        = network_utils::ipv4_to_string(ip_uint);
            ip_info.iface_idx = if_nametoindex(ifr.ifr_name);

            if (ioctl(fd, SIOCGIFNETMASK, &ifr) == -1) {
                ip_info.netmask.clear();
            } else {
                ip_uint         = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
                ip_info.netmask = network_utils::ipv4_to_string(ip_uint);
            }

            ip_uint = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr) |
                      (~(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr));
            ip_info.broadcast_ip = network_utils::ipv4_to_string(ip_uint);

            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
                ip_info.mac.clear();
            } else {
                ip_info.mac = tlvf::mac_to_string((uint8_t *)(ifr.ifr_ifru.ifru_hwaddr.sa_data));
                std::transform(ip_info.mac.begin(), ip_info.mac.end(), ip_info.mac.begin(),
                               ::tolower);
            }
            ip_list.push_back(ip_info);
        }
    }
    delete[] msgBuf;
    close(sock);
    close(fd);
    // update gw ip
    for (auto &ip_item : ip_list) {
        LOG(DEBUG) << "ip_item iface=" << ip_item.iface;
        if (ip_item.iface == gw_ip_info.iface) {
            ip_item.gw = gw_ip_info.gw;
        }
    }
    return ip_list;
}

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

bool bpl_network::remove_iface_from_bridge(const std::string &bridge, const std::string &iface)
{
    LOG(DEBUG) << "remove iface " << iface << " from bridge " << bridge;

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
#ifdef SIOCBRDELIF
    ifr.ifr_ifindex = ifindex;
    err             = ioctl(br_socket_fd, SIOCBRDELIF, &ifr);
    if (err < 0)
#endif
    {
        unsigned long args[4] = {BRCTL_DEL_IF, ifindex, 0, 0};

        ifr.ifr_data = (char *)args;
        err          = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);
    }

    close(br_socket_fd);
    return err < 0 ? false : true;
    /*
    std::string cmd;
    cmd = "brctl delif " + bridge + " " + iface;
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

bool bpl_network::iface_get_mac(const std::string &iface, std::string &mac)
{
    struct ifreq ifr;
    int fd;

    mac.clear();

    if (iface.empty()) {
        LOG(ERROR) << "Empty interface name";
        return false;
    }

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG(ERROR) << "Can't open SOCK_DGRAM socket";
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    string_utils::copy_string(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        LOG(ERROR) << "SIOCGIFHWADDR. iface: " << iface;
        close(fd);
        return false;
    }
    close(fd);
    mac = tlvf::mac_to_string((uint8_t *)(ifr.ifr_ifru.ifru_hwaddr.sa_data));
    std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
    return true;
}

bool bpl_network::iface_get_ip(const std::string &iface, std::string &ip)
{
    struct ifreq ifr;
    int fd;

    ip.clear();

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG(ERROR) << "Can't open SOCK_DGRAM socket";
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    string_utils::copy_string(ifr.ifr_name, iface.c_str(), IFNAMSIZ);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        LOG(ERROR) << "SIOCGIFADDR";
        close(fd);
        return false;
    }
    close(fd);
    uint32_t ip_uint = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    ip               = network_utils::ipv4_to_string(ip_uint);
    return true;
}

bool bpl_network::iface_get_name(const sMacAddr &mac, std::string &iface)
{
    bool found = false;
    struct if_nameindex *pif;
    struct if_nameindex *head;
    std::string mac_to_find = tlvf::mac_to_string(mac);

    head = pif = if_nameindex();
    while (pif->if_index && (!found)) {
        std::string if_mac;
        if (iface_get_mac(pif->if_name, if_mac) && (if_mac == mac_to_find)) {
            iface = pif->if_name;
            found = true;
        }
        pif++;
    }

    if_freenameindex(head);

    return found;
}

bool bpl_network::iface_get_host_bridge(const std::string &iface, std::string &bridge)
{
    bridge.clear();
    std::string bridge_path("/sys/class/net/" + iface + "/brport/bridge");
    char resolvedPath[PATH_MAX];
    if (!realpath(bridge_path.c_str(), resolvedPath)) {
        return false;
    }
    std::string pathStr = resolvedPath;
    bridge              = pathStr.substr(pathStr.rfind('/') + 1);
    return true;
}

bool bpl_network::get_iface_info(network_utils::iface_info &info, const std::string &iface_name)
{
    info.iface = iface_name;
    info.mac.clear();
    info.ip.clear();
    info.netmask.clear();
    info.ip_gw.clear();

    std::vector<network_utils::ip_info> ip_list = get_ip_list();
    for (auto &ip_info : ip_list) {
        LOG(INFO) << "iacobtest " << ip_info.mac;
        if (ip_info.iface == iface_name) {
            info.mac          = ip_info.mac;
            info.ip           = ip_info.ip;
            info.netmask      = ip_info.netmask;
            info.ip_gw        = ip_info.gw;
            info.broadcast_ip = ip_info.broadcast_ip;
            break;
        }
    }

    if (info.mac.empty()) {
        if (!iface_get_mac(iface_name, info.mac)) {
            return false;
        }
    }

    return true;
}

} // namespace bpl
} // namespace beerocks
