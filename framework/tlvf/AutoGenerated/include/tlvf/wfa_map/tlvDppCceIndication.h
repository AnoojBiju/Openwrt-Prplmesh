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

#ifndef _TLVF_WFA_MAP_TLVDPPCCEINDICATION_H_
#define _TLVF_WFA_MAP_TLVDPPCCEINDICATION_H_

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


class tlvDppCceIndication : public BaseClass
{
    public:
        tlvDppCceIndication(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvDppCceIndication(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvDppCceIndication();

        enum eAdvertiseCee: uint8_t {
            DISABLE = 0x0,
            ENABLE = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eAdvertiseCee_str(eAdvertiseCee enum_value) {
            switch (enum_value) {
            case DISABLE: return "DISABLE";
            case ENABLE:  return "ENABLE";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eAdvertiseCee value) { return out << eAdvertiseCee_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        eAdvertiseCee& advertise_cee();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eAdvertiseCee* m_advertise_cee = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVDPPCCEINDICATION_H_
