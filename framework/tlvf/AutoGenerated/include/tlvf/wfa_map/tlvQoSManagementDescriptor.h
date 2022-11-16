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

#ifndef _TLVF_WFA_MAP_TLVQOSMANAGEMENTDESCRIPTOR_H_
#define _TLVF_WFA_MAP_TLVQOSMANAGEMENTDESCRIPTOR_H_

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


class tlvQoSManagementDescriptor : public BaseClass
{
    public:
        tlvQoSManagementDescriptor(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvQoSManagementDescriptor(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvQoSManagementDescriptor();

        const eTlvTypeMap& type();
        const uint16_t& length();
        //An identifier that uniquely identifies a QoS Management rule
        uint16_t& qmid();
        //BSSID of BSS for which this descriptor applies
        sMacAddr& bssid();
        //MAC address of STA for which this descriptor applies
        sMacAddr& client_mac();
        //One of:
        //  - MSCS Descriptor element (as described in 9.4.2.243 of IEEE 802.11-2020) or
        //  - SCS Descriptor element (as described in 9.4.2.121 of IEEE 802.11-2020) or
        //  - QoS Management element (as described in 5.3 of QoS Management Specification R2)
        size_t descriptor_element_length() { return m_descriptor_element_idx__ * sizeof(uint8_t); }
        uint8_t* descriptor_element(size_t idx = 0);
        bool set_descriptor_element(const void* buffer, size_t size);
        bool alloc_descriptor_element(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint16_t* m_qmid = nullptr;
        sMacAddr* m_bssid = nullptr;
        sMacAddr* m_client_mac = nullptr;
        uint8_t* m_descriptor_element = nullptr;
        size_t m_descriptor_element_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVQOSMANAGEMENTDESCRIPTOR_H_
