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

#ifndef _TLVF_WFA_MAP_TLVANTICIPATEDCHANNELPREFERENCE_H_
#define _TLVF_WFA_MAP_TLVANTICIPATEDCHANNELPREFERENCE_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>
#include <vector>

namespace wfa_map {

class cAnticipatedOperatingClasses;

class tlvAnticipatedChannelPreference : public BaseClass
{
    public:
        tlvAnticipatedChannelPreference(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAnticipatedChannelPreference(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAnticipatedChannelPreference();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& operating_classes_list_length();
        std::tuple<bool, cAnticipatedOperatingClasses&> operating_classes_list(size_t idx);
        std::shared_ptr<cAnticipatedOperatingClasses> create_operating_classes_list();
        bool add_operating_classes_list(std::shared_ptr<cAnticipatedOperatingClasses> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_operating_classes_list_length = nullptr;
        cAnticipatedOperatingClasses* m_operating_classes_list = nullptr;
        size_t m_operating_classes_list_idx__ = 0;
        std::vector<std::shared_ptr<cAnticipatedOperatingClasses>> m_operating_classes_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cAnticipatedOperatingClasses : public BaseClass
{
    public:
        cAnticipatedOperatingClasses(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAnticipatedOperatingClasses(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAnticipatedOperatingClasses();

        uint8_t& operating_class();
        uint8_t& channel_list_length();
        uint8_t* channel_list(size_t idx = 0);
        bool set_channel_list(const void* buffer, size_t size);
        bool alloc_channel_list(size_t count = 1);
        uint32_t& reserved();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_operating_class = nullptr;
        uint8_t* m_channel_list_length = nullptr;
        uint8_t* m_channel_list = nullptr;
        size_t m_channel_list_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint32_t* m_reserved = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVANTICIPATEDCHANNELPREFERENCE_H_
