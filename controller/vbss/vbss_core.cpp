//
// Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//
#include "vbss_core.h"

namespace vbss {

/**
 * @brief Compare ethernet addresses
 *
 * @param eth1
 * @param eth2
 * @return -1 if eth1 is greater; 0 if addresses are equal; 1 if eth2 is greater
 */

//static int8_t comp_eth_addrs(const uint8_t eth1[ETH_ALEN], const uint8_t eth2[ETH_ALEN])
static int8_t comp_eth_addrs(const uint8_t eth1[ETH_ALEN], const vbss::vbss_id &eth2)
{
    for (uint8_t i = 0; i < ETH_ALEN; ++i) {
        if (eth1[i] > eth2[1])
            return -1;
        else if (eth1[i] < eth2[i])
            return 1;
        else
            continue;
    }
    return 0;
}

/*static void copy_eth_addrs(const uint8_t eth1[ETH_ALEN], uint8_t eth2[ETH_ALEN])
{
    for (uint8_t i = 0; i < ETH_ALEN; ++i) {
        eth2[i] = eth1[i];
    }
}
*/
VbssCore::VbssCore() {}

VbssCore::~VbssCore() {}

bool VbssCore::create_set_of_vbss_ids(const uint8_t bssid_orig[ETH_ALEN],
                                      const uint8_t fixed_mask[ETH_ALEN],
                                      const uint8_t fixed_bits[ETH_ALEN],
                                      const uint8_t &max_numbers,
                                      std::vector<vbss_id> &vbss_id_list)
{
    // Perform the required functionality to get the list of vbss_ids that this agent can handle
    // First determine what restrictions we are under
    //uint8_t zero_addr[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
    vbss_id zero_addr = {0, 0, 0, 0, 0, 0};
    // First check for the easy solution
    if (0 != comp_eth_addrs(fixed_bits, zero_addr)) {

        vbss::vbss_id tmp_id = {0, 0, 0, 0, 0, 0};

        uint8_t fixed_byte = copy_fixed_and_base(fixed_bits, bssid_orig, tmp_id);
        if (fixed_byte == ETH_ALEN) {
            return false;
        }
        // Now the fun part; generate the fake bssids
        // One byte can hold 256 values we can just increment the last byte by one
        vbss_id_list.clear();
        //Increment byte 5 +1 so we can verify nothing we set will interfere with the created values
        tmp_id[ETH_ALEN - 2] += 1;
        // Set last hex to 0000 0001
        uint8_t last_hex = 1;
        for (uint8_t bssid_it = 0; bssid_it < max_numbers; ++bssid_it) {
            tmp_id[ETH_ALEN - 1] = last_hex++;
            vbss_id_list.push_back(tmp_id);
        }
    } else if (0 != comp_eth_addrs(fixed_mask, zero_addr)) {
        // If we are here then we have restrictions, generated ids need to be bit orthogonal
        // Ex: Base == AA:BB:CC:00:11:22 first generated must be AA:BB:CC:00:11:2{4,6,8,A}
        vbss_id base_id    = {0, 0, 0, 0, 0, 0};
        uint8_t fixed_byte = copy_fixed_and_base(fixed_mask, bssid_orig, base_id);
        vbss_id tmp_bssid  = {base_id[0], base_id[1], base_id[2],
                              base_id[3], base_id[4], base_id[5]};

        for (uint8_t idx = ETH_ALEN - 1; idx >= fixed_byte; --idx) {
            std::vector<uint8_t> mac_byte_values = determine_orthogonal_vals(base_id[idx]);
            for (const auto &it : mac_byte_values) {
                tmp_bssid[idx] = it;
                vbss_id_list.push_back(tmp_bssid);
            }
            // Reset value
            tmp_bssid[idx] = base_id[idx];
            if (max_numbers <= vbss_id_list.size())
                break;
        }
    }
    return true;
}

uint8_t VbssCore::copy_fixed_and_base(const uint8_t fixed[ETH_ALEN], const uint8_t base[ETH_ALEN],
                                      vbss::vbss_id &tmp_bssid)
{
    uint8_t ret_byte = 0;
    for (uint8_t b_val = 0; b_val < ETH_ALEN; ++b_val) {
        if (fixed[b_val] != 0) {
            tmp_bssid[b_val] = fixed[b_val];
        } else {
            if (ret_byte == 0)
                ret_byte = b_val;
            tmp_bssid[b_val] = base[b_val];
        }
    }

    return ret_byte;
}

std::vector<uint8_t> VbssCore::determine_orthogonal_vals(const uint8_t &b_val)
{
    std::vector<uint8_t> ret_val;
    uint8_t orthog_mac = ~b_val;

    for (int i = 0; i <= BYTE_LEN; ++i) {
        uint8_t tmp_val = 1 << i;
        if ((tmp_val & orthog_mac) == tmp_val && tmp_val != 0) {
            ret_val.push_back(tmp_val);
        }
    }
    return ret_val;
}

}
