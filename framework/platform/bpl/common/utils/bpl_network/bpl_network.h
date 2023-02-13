/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2023 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BPL_NETWORK_H_
#define _BPL_NETWORK_H_

//#include <bcl/beerocks_os_utils.h>

#include <cstdint>
#include <list>
#include <string>
#include <vector>

//#include <netinet/ether.h>

//#include <bcl/network/net_struct>
//#include <bcl/network/network_utils.h>
//#include <bcl/network/socket.h>
/*
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define ARP_HDRLEN 28 // ARP header length
// Define some constants.
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1 // Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2
#endif
*/

namespace beerocks {
namespace bpl {

constexpr uint16_t MIN_VLAN_ID = 1;
constexpr uint16_t MAX_VLAN_ID = 4094;

// According to 802.11-2016 convertion table (Table 9-154).

class bpl_network {
public:
    /**
     * @brief Get list of linux interfaces.
     *
     * @param [in] name of the bridge interface
     * @return std::vector<std::string> of interface names that belong to the bridge
     */
    static std::vector<std::string> get_iface_list_from_bridge(const std::string &bridge);

    /**
     * @brief Add the interface iface to the bridge
     *
     * @param[in] bridge the bridge to which the interface is to be added
     * @param[in] iface  the interface to be added to the bridge
     * @return bool
    */
    static bool add_iface_to_bridge(const std::string &bridge, const std::string &iface);
};
} // namespace bpl
} // namespace beerocks

#endif // _BPL_NETWORK_H_
