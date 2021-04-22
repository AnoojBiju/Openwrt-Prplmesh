/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include <bcl/network/network_utils.h>
#include <bpl/bpl_dhcp.h>
#include <tlvf/tlvftypes.h>

extern "C" {
// Ignore some warnings from libubus
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <libubox/blobmsg.h>
#include <libubus.h>
}

const unsigned UBUS_CALL_TIMEOUT_MS = 100;
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

namespace beerocks {
namespace bpl {

static ubus_context *s_pUbusCtx = nullptr;

// lucy-rpc dhcp leases policy
enum {
    DHCP_IPV4_LEASES,
    DHCP_IPV6_LEASES,
};

static const blobmsg_policy dhcp_lease_policy[] = {
    [DHCP_IPV4_LEASES] = {.name = "dhcp_leases", .type = BLOBMSG_TYPE_ARRAY},
    [DHCP_IPV6_LEASES] = {.name = "dhcp6_leases", .type = BLOBMSG_TYPE_ARRAY},
};

// lucy-rpc dhcp ipv4 lease policy
enum {
    IPV4_EXPIRES,
    IPV4_HOSTNAME,
    IPV4_MAC_ADDRESS,
    IPV4_DUID,
    IPV4_IP_ADDRESS,
};

static const blobmsg_policy ipv4_lease_policy[] = {
    [IPV4_EXPIRES]     = {.name = "expires", .type = BLOBMSG_TYPE_INT32},
    [IPV4_HOSTNAME]    = {.name = "hostname", .type = BLOBMSG_TYPE_STRING},
    [IPV4_MAC_ADDRESS] = {.name = "macaddr", .type = BLOBMSG_TYPE_STRING},
    [IPV4_DUID]        = {.name = "duid", .type = BLOBMSG_TYPE_STRING},
    [IPV4_IP_ADDRESS]  = {.name = "ipaddr", .type = BLOBMSG_TYPE_STRING}};

// lucy-rpc dhcp ipv6 lease policy
enum {
    IPV6_EXPIRES,
    IPV6_HOSTNAME,
    IPV6_DUID,
    IPV6_IP_ADDRESS,
    IPV6_IP_ADDRESSES,
};

static const blobmsg_policy ipv6_lease_policy[] = {
    [IPV6_EXPIRES]      = {.name = "expires", .type = BLOBMSG_TYPE_INT32},
    [IPV6_HOSTNAME]     = {.name = "hostname", .type = BLOBMSG_TYPE_STRING},
    [IPV6_DUID]         = {.name = "duid", .type = BLOBMSG_TYPE_STRING},
    [IPV6_IP_ADDRESS]   = {.name = "ip6addr", .type = BLOBMSG_TYPE_STRING},
    [IPV6_IP_ADDRESSES] = {.name = "ip6addrs", .type = BLOBMSG_TYPE_ARRAY}};

int dhcp_mon_start(dhcp_mon_cb cb) { return -2; }

int dhcp_mon_handle_event() { return 0; }

int dhcp_mon_stop() { return 0; }

bool dhcp_manual_procedure_init()
{
    // Prevent multiple instances.
    if (s_pUbusCtx) {
        return true;
    }

    // Use default ubus socket
    s_pUbusCtx = ubus_connect(NULL);

    if (!s_pUbusCtx) {
        LOG(ERROR) << "ubus_connect() is failed";
        return false;
    }
    return true;
}

static void lease_data_handler(ubus_request *req, int type, blob_attr *msg)
{
    if (!msg || !req->priv) {
        return;
    }

    auto leases_map = static_cast<leases_pair_t *>(req->priv);
    leases_map->first.clear();
    leases_map->second.clear();

    blob_attr *tb[ARRAY_SIZE(dhcp_lease_policy)];

    if (blobmsg_parse(dhcp_lease_policy, ARRAY_SIZE(dhcp_lease_policy), tb, blobmsg_data(msg),
                      blobmsg_data_len(msg)) != 0) {
        LOG(ERROR) << "Parse failed with dhcp_lease_policy";
        return;
    }

    if (tb[DHCP_IPV4_LEASES]) {

        blob_attr *attr;
        auto head = blobmsg_data(tb[DHCP_IPV4_LEASES]);
        auto len  = blobmsg_data_len(tb[DHCP_IPV4_LEASES]);

        // Iterate over all IPv4 Leases
        __blob_for_each_attr(attr, head, len)
        {
            blob_attr *tb_ipv4[ARRAY_SIZE(ipv4_lease_policy)];

            if (blobmsg_parse(ipv4_lease_policy, ARRAY_SIZE(ipv4_lease_policy), tb_ipv4,
                              blobmsg_data(attr), blobmsg_data_len(attr)) != 0) {

                LOG(ERROR) << "Parse failed with ipv4_lease_policy";
                continue;
            }

            if (tb_ipv4[IPV4_MAC_ADDRESS]) {
                sMacAddr mac = tlvf::mac_from_string(blobmsg_get_string(tb_ipv4[IPV4_MAC_ADDRESS]));

                sIPv4Lease lease;

                if (tb_ipv4[IPV4_IP_ADDRESS]) {
                    lease.ip_address.assign(blobmsg_get_string(tb_ipv4[IPV4_IP_ADDRESS]));
                }
                if (tb_ipv4[IPV4_HOSTNAME]) {
                    lease.host_name.assign(blobmsg_get_string(tb_ipv4[IPV4_HOSTNAME]));
                }

                leases_map->first.insert(std::make_pair(mac, lease));
            }
        }
    }

    if (tb[DHCP_IPV6_LEASES]) {

        blob_attr *attr;
        auto head = blobmsg_data(tb[DHCP_IPV6_LEASES]);
        auto len  = blobmsg_data_len(tb[DHCP_IPV6_LEASES]);

        // Iterate over all IPv6 Leases
        __blob_for_each_attr(attr, head, len)
        {
            blob_attr *tb_ipv6[ARRAY_SIZE(ipv6_lease_policy)];

            if (blobmsg_parse(ipv6_lease_policy, ARRAY_SIZE(ipv6_lease_policy), tb_ipv6,
                              blobmsg_data(attr), blobmsg_data_len(attr)) != 0) {

                LOG(ERROR) << "Parse failed with ipv6_lease_policy";
                continue;
            }

            if (tb_ipv6[IPV6_DUID]) {

                // TODO Get MAC over DUID (PPM-535)
                sMacAddr mac = beerocks::net::network_utils::ZERO_MAC;
                sIPv6Lease lease;

                if (tb_ipv6[IPV6_IP_ADDRESS]) {
                    lease.ip_address.assign(blobmsg_get_string(tb_ipv6[IPV6_IP_ADDRESS]));
                }
                if (tb_ipv6[IPV6_HOSTNAME]) {
                    lease.host_name.assign(blobmsg_get_string(tb_ipv6[IPV6_HOSTNAME]));
                }

                leases_map->second.insert(std::make_pair(mac, lease));
            }
        }
    }

    return;
}

bool dhcp_get_leases(leases_pair_t &leases_map)
{
    int ret_val;
    uint32_t id;

    // Check for successful init.
    if (!s_pUbusCtx) {
        LOG(ERROR) << "Uninitialized ubus context";
        return false;
    }

    if (ubus_lookup_id(s_pUbusCtx, "luci-rpc", &id)) {
        LOG(ERROR) << "Failed to look up luci-rpc";
        return false;
    }

    ret_val = ubus_invoke(s_pUbusCtx, id, "getDHCPLeases", nullptr, lease_data_handler,
                          static_cast<void *>(&leases_map), UBUS_CALL_TIMEOUT_MS);

    return (ret_val == 0);
}

} // namespace bpl
} // namespace beerocks
