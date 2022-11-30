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

#ifndef _TLVF_WFA_MAP_TLVUNASSOCIATEDSTALINKMETRICSQUERY_H_
#define _TLVF_WFA_MAP_TLVUNASSOCIATEDSTALINKMETRICSQUERY_H_

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
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {

class cChannelParameters;

class tlvUnassociatedStaLinkMetricsQuery : public BaseClass
{
    public:
        tlvUnassociatedStaLinkMetricsQuery(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvUnassociatedStaLinkMetricsQuery(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvUnassociatedStaLinkMetricsQuery();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& operating_class_of_channel_list();
        uint8_t& channel_list_length();
        std::tuple<bool, cChannelParameters&> channel_list(size_t idx);
        std::shared_ptr<cChannelParameters> create_channel_list();
        bool add_channel_list(std::shared_ptr<cChannelParameters> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_operating_class_of_channel_list = nullptr;
        uint8_t* m_channel_list_length = nullptr;
        cChannelParameters* m_channel_list = nullptr;
        size_t m_channel_list_idx__ = 0;
        std::vector<std::shared_ptr<cChannelParameters>> m_channel_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cChannelParameters : public BaseClass
{
    public:
        cChannelParameters(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cChannelParameters(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cChannelParameters();

        uint8_t& channel_number();
        uint8_t& sta_list_length();
        std::tuple<bool, sMacAddr&> sta_list(size_t idx);
        bool alloc_sta_list(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_channel_number = nullptr;
        uint8_t* m_sta_list_length = nullptr;
        sMacAddr* m_sta_list = nullptr;
        size_t m_sta_list_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVUNASSOCIATEDSTALINKMETRICSQUERY_H_
