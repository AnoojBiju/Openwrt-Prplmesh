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

#ifndef _TLVF_WFA_MAP_TLVQOSMANAGEMENTPOLICY_H_
#define _TLVF_WFA_MAP_TLVQOSMANAGEMENTPOLICY_H_

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


class tlvQoSManagementPolicy : public BaseClass
{
    public:
        tlvQoSManagementPolicy(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvQoSManagementPolicy(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvQoSManagementPolicy();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& mscs_disallowed_sta_length();
        std::tuple<bool, sMacAddr&> mscs_disallowed_sta_list(size_t idx);
        bool alloc_mscs_disallowed_sta_list(size_t count = 1);
        uint8_t& scs_disallowed_sta_length();
        std::tuple<bool, sMacAddr&> scs_disallowed_sta_list(size_t idx);
        bool alloc_scs_disallowed_sta_list(size_t count = 1);
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_mscs_disallowed_sta_length = nullptr;
        sMacAddr* m_mscs_disallowed_sta_list = nullptr;
        size_t m_mscs_disallowed_sta_list_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_scs_disallowed_sta_length = nullptr;
        sMacAddr* m_scs_disallowed_sta_list = nullptr;
        size_t m_scs_disallowed_sta_list_idx__ = 0;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVQOSMANAGEMENTPOLICY_H_
