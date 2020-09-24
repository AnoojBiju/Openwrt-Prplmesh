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

#ifndef _TLVF_WFA_MAP_TLVTUNNELLEDSOURCEINFO_H_
#define _TLVF_WFA_MAP_TLVTUNNELLEDSOURCEINFO_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class tlvTunnelledSourceInfo : public BaseClass
{
    public:
        tlvTunnelledSourceInfo(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTunnelledSourceInfo(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTunnelledSourceInfo();

        const eTlvTypeMap& type();
        const uint16_t& length();
        //The MAC address of the device that generated the message included in the tlvValue field of the Tunneled TLV.
        sMacAddr& mac();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_mac = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTUNNELLEDSOURCEINFO_H_
