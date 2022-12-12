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

#ifndef _TLVF_WFA_MAP_TLVPROFILE2APRADIOADVANCEDCAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVPROFILE2APRADIOADVANCEDCAPABILITIES_H_

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


class tlvProfile2ApRadioAdvancedCapabilities : public BaseClass
{
    public:
        tlvProfile2ApRadioAdvancedCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvProfile2ApRadioAdvancedCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvProfile2ApRadioAdvancedCapabilities();

        typedef struct sAdvancedRadioCapabilities {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 2;
            uint8_t dscp_policy : 1;
            uint8_t dscp_to_up_mapping : 1;
            uint8_t scs : 1;
            uint8_t mscs : 1;
            uint8_t combined_profile1_and_profile2 : 1;
            uint8_t combined_front_back : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t combined_front_back : 1;
            uint8_t combined_profile1_and_profile2 : 1;
            uint8_t mscs : 1;
            uint8_t scs : 1;
            uint8_t dscp_to_up_mapping : 1;
            uint8_t dscp_policy : 1;
            uint8_t reserved : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sAdvancedRadioCapabilities;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& radio_uid();
        sAdvancedRadioCapabilities& advanced_radio_capabilities();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_radio_uid = nullptr;
        sAdvancedRadioCapabilities* m_advanced_radio_capabilities = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVPROFILE2APRADIOADVANCEDCAPABILITIES_H_
