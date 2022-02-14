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

#ifndef _TLVF_WFA_MAP_TLVASSOCIATEDWIFI6STASTATUSREPORT_H_
#define _TLVF_WFA_MAP_TLVASSOCIATEDWIFI6STASTATUSREPORT_H_

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

class cTidQueueSize;

class tlvAssociatedWiFi6StaStatusReport : public BaseClass
{
    public:
        tlvAssociatedWiFi6StaStatusReport(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAssociatedWiFi6StaStatusReport(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAssociatedWiFi6StaStatusReport();

        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& sta_mac();
        uint8_t& tid_queue_size_list_length();
        std::tuple<bool, cTidQueueSize&> tid_queue_size_list(size_t idx);
        std::shared_ptr<cTidQueueSize> create_tid_queue_size_list();
        bool add_tid_queue_size_list(std::shared_ptr<cTidQueueSize> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_sta_mac = nullptr;
        uint8_t* m_tid_queue_size_list_length = nullptr;
        cTidQueueSize* m_tid_queue_size_list = nullptr;
        size_t m_tid_queue_size_list_idx__ = 0;
        std::vector<std::shared_ptr<cTidQueueSize>> m_tid_queue_size_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cTidQueueSize : public BaseClass
{
    public:
        cTidQueueSize(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cTidQueueSize(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cTidQueueSize();

        //The Tid of the corresponing queue size field. 
        uint8_t& tid();
        //Queue size of associated TID field.
        uint8_t& queue_size();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_tid = nullptr;
        uint8_t* m_queue_size = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVASSOCIATEDWIFI6STASTATUSREPORT_H_
