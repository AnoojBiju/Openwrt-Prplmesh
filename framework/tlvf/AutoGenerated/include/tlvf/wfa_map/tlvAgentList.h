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

#ifndef _TLVF_WFA_MAP_TLVAGENTLIST_H_
#define _TLVF_WFA_MAP_TLVAGENTLIST_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>
#include <ostream>
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class tlvAgentList : public BaseClass
{
    public:
        tlvAgentList(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAgentList(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAgentList();

        enum eMultiApProfile: uint8_t {
            MULTIAP_PROFILE_1 = 0x1,
            MULTIAP_PROFILE_2 = 0x2,
            MULTIAP_PROFILE_3 = 0x3,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eMultiApProfile_str(eMultiApProfile enum_value) {
            switch (enum_value) {
            case MULTIAP_PROFILE_1: return "MULTIAP_PROFILE_1";
            case MULTIAP_PROFILE_2: return "MULTIAP_PROFILE_2";
            case MULTIAP_PROFILE_3: return "MULTIAP_PROFILE_3";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eMultiApProfile value) { return out << eMultiApProfile_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        enum eSecurity: uint8_t {
            IEEE1905_NOT_ENABLED = 0x0,
            IEEE1905_ENABLED = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eSecurity_str(eSecurity enum_value) {
            switch (enum_value) {
            case IEEE1905_NOT_ENABLED: return "IEEE1905_NOT_ENABLED";
            case IEEE1905_ENABLED:     return "IEEE1905_ENABLED";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eSecurity value) { return out << eSecurity_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        typedef struct sAgent {
            sMacAddr al_mac;
            eMultiApProfile multi_ap_profile;
            eSecurity security;
            void struct_swap(){
                al_mac.struct_swap();
                tlvf_swap(8*sizeof(eMultiApProfile), reinterpret_cast<uint8_t*>(&multi_ap_profile));
                tlvf_swap(8*sizeof(eSecurity), reinterpret_cast<uint8_t*>(&security));
            }
            void struct_init(){
                al_mac.struct_init();
            }
        } __attribute__((packed)) sAgent;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& number_of_agents();
        std::tuple<bool, sAgent&> agents(size_t idx);
        bool alloc_agents(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_number_of_agents = nullptr;
        sAgent* m_agents = nullptr;
        size_t m_agents_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAGENTLIST_H_
