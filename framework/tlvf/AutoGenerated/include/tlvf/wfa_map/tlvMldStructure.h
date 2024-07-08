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

#ifndef _TLVF_WFA_MAP_TLVMLDSTRUCTURE_H_
#define _TLVF_WFA_MAP_TLVMLDSTRUCTURE_H_

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
#include <vector>

namespace wfa_map {

class cAffiliated;

class tlvMldStructure : public BaseClass
{
    public:
        tlvMldStructure(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvMldStructure(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvMldStructure();

        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& mld_mac_addr();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint8_t& num_affiliated();
        std::tuple<bool, cAffiliated&> affiliated(size_t idx);
        std::shared_ptr<cAffiliated> create_affiliated();
        bool add_affiliated(std::shared_ptr<cAffiliated> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_mld_mac_addr = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_affiliated = nullptr;
        cAffiliated* m_affiliated = nullptr;
        size_t m_affiliated_idx__ = 0;
        std::vector<std::shared_ptr<cAffiliated>> m_affiliated_vector;
        bool m_lock_allocation__ = false;
};

class cAffiliated : public BaseClass
{
    public:
        cAffiliated(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAffiliated(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAffiliated();

        sMacAddr& affiliated_mac_addr();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_affiliated_mac_addr = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVMLDSTRUCTURE_H_
