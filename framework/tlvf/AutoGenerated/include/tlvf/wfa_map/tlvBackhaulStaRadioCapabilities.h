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

#ifndef _TLVF_WFA_MAP_TLVBACKHAULSTARADIOCAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVBACKHAULSTARADIOCAPABILITIES_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"
#include <asm/byteorder.h>

namespace wfa_map {


class tlvBackhaulStaRadioCapabilities : public BaseClass
{
    public:
        tlvBackhaulStaRadioCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvBackhaulStaRadioCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvBackhaulStaRadioCapabilities();

        typedef struct sStaMacIncluded {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t mac_included : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t mac_included : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sStaMacIncluded;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        //Radio Unique Identifier of the radio for which capabilities are reported.
        sMacAddr& ruid();
        sStaMacIncluded& sta_mac_included();
        //Mac Address of the backhaul STA on this radio.
        //This field is included if the MAC address included field is set to 1.
        sMacAddr& sta_mac();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_ruid = nullptr;
        sStaMacIncluded* m_sta_mac_included = nullptr;
        sMacAddr* m_sta_mac = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVBACKHAULSTARADIOCAPABILITIES_H_
