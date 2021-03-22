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

#ifndef _TLVF_WFA_MAP_TLVPROFILE2MULTIAPPROFILE_H_
#define _TLVF_WFA_MAP_TLVPROFILE2MULTIAPPROFILE_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"

namespace wfa_map {


class tlvProfile2MultiApProfile : public BaseClass
{
    public:
        tlvProfile2MultiApProfile(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvProfile2MultiApProfile(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvProfile2MultiApProfile();

        enum eMultiApProfile: uint8_t {
            MULTIAP_PROFILE_UNKNOWN = 0x0,
            MULTIAP_PROFILE_1 = 0x1,
            MULTIAP_PROFILE_2 = 0x2,
        };
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        eMultiApProfile& profile();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eMultiApProfile* m_profile = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVPROFILE2MULTIAPPROFILE_H_
