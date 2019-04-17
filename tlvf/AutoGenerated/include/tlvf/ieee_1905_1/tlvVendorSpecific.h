///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/*
#############################################################################
# INTEL CONFIDENTIAL
# Copyright 2018 Intel Corporation All Rights Reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its
# suppliers or licensors.  Title to the Material remains with Intel
# Corporation or its suppliers and licensors.  The Material contains trade
# secrets and proprietary and confidential information of Intel or its
# suppliers and licensors.  The Material is protected by worldwide copyright
# and trade secret laws and treaty provisions. No part of the Material may
# be used, copied, reproduced, modified, published, uploaded, posted,
# transmitted, distributed, or disclosed in any way without Intel's prior
# express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or
# delivery of the Materials,  either expressly, by implication, inducement,
# estoppel or otherwise.  Any license under such intellectual property
# rights must be express and approved by Intel in writing.
#############################################################################
*/

#ifndef _TLVF_IEEE_1905_1_TLVVENDORSPECIFIC_H_
#define _TLVF_IEEE_1905_1_TLVVENDORSPECIFIC_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include "tlvf/ieee_1905_1/eTlvType.h"
#include <tuple>

namespace ieee1905_1 {


class tlvVendorSpecific : public BaseClass
{
    public:
        tlvVendorSpecific(uint8_t* buff, size_t buff_len, bool parse = false, bool swap_needed = false);
        tlvVendorSpecific(std::shared_ptr<BaseClass> base, bool parse = false, bool swap_needed = false);
        ~tlvVendorSpecific();

        enum eVendorOUI: uint32_t {
            OUI_BYTES = 0x3,
            OUI_INTEL = 0x0,
        };
        
        const eTlvType& type();
        uint16_t& length();
        //Use eVendorOUI
        std::tuple<bool, uint8_t&> vendor_oui(size_t idx);
        void class_swap();
        static size_t get_initial_size();

    private:
        bool init();
        eTlvType* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_vendor_oui = nullptr;
        size_t m_vendor_oui_idx__ = 0;
};

}; // close namespace: ieee1905_1

#endif //_TLVF/IEEE_1905_1_TLVVENDORSPECIFIC_H_
