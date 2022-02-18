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

#ifndef _TLVF_WFA_MAP_TLVTUNNELLEDPROTOCOLTYPE_H_
#define _TLVF_WFA_MAP_TLVTUNNELLEDPROTOCOLTYPE_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <ostream>

namespace wfa_map {


class tlvTunnelledProtocolType : public BaseClass
{
    public:
        tlvTunnelledProtocolType(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTunnelledProtocolType(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTunnelledProtocolType();

        enum eTunnelledProtocolType: uint8_t {
            ASSOCIATION_REQUEST = 0x0,
            REASSOCIATION_REQUEST = 0x1,
            BTM_QUERY = 0x2,
            WNM_REQUEST = 0x3,
            ANQP_REQUEST = 0x4,
        };
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        //802.11 request frame type carried in the Tunnelled TLV.
        eTunnelledProtocolType& protocol_type();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eTunnelledProtocolType* m_protocol_type = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTUNNELLEDPROTOCOLTYPE_H_
