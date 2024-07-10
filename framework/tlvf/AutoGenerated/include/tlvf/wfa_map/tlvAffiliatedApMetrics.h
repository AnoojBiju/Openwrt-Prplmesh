///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_WFA_MAP_TLVAFFILIATEDAPMETRICS_H_
#define _TLVF_WFA_MAP_TLVAFFILIATEDAPMETRICS_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"
#include <tuple>

namespace wfa_map {


class tlvAffiliatedApMetrics : public BaseClass
{
    public:
        tlvAffiliatedApMetrics(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAffiliatedApMetrics(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAffiliatedApMetrics();

        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& bssid();
        uint32_t& packets_sent();
        uint32_t& packets_received();
        uint32_t& packets_sent_errors();
        uint32_t& unicast_byte_sent();
        uint32_t& unicast_byte_received();
        uint32_t& multicast_byte_sent();
        uint32_t& multicast_byte_received();
        uint32_t& broadcast_byte_sent();
        uint32_t& broadcast_byte_received();
        //Reserved for future expansion (length inferred from tlvLength field)
        size_t reserved_length() { return m_reserved_idx__ * sizeof(uint8_t); }
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        bool alloc_reserved(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_bssid = nullptr;
        uint32_t* m_packets_sent = nullptr;
        uint32_t* m_packets_received = nullptr;
        uint32_t* m_packets_sent_errors = nullptr;
        uint32_t* m_unicast_byte_sent = nullptr;
        uint32_t* m_unicast_byte_received = nullptr;
        uint32_t* m_multicast_byte_sent = nullptr;
        uint32_t* m_multicast_byte_received = nullptr;
        uint32_t* m_broadcast_byte_sent = nullptr;
        uint32_t* m_broadcast_byte_received = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAFFILIATEDAPMETRICS_H_
