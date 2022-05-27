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

#ifndef _TLVF_WFA_MAP_TLVBSSCONFIGURATIONRESPONSE_H_
#define _TLVF_WFA_MAP_TLVBSSCONFIGURATIONRESPONSE_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>

namespace wfa_map {


class tlvBssConfigurationResponse : public BaseClass
{
    public:
        tlvBssConfigurationResponse(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvBssConfigurationResponse(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvBssConfigurationResponse();

        const eTlvTypeMap& type();
        const uint16_t& length();
        //One or more JSON encoded DPP Configuration Object attributes (See section 8.1 of Wi-Fi Easy
        //Connect Specification).
        size_t dpp_configuration_object_length() { return m_dpp_configuration_object_idx__ * sizeof(uint8_t); }
        uint8_t* dpp_configuration_object(size_t idx = 0);
        bool set_dpp_configuration_object(const void* buffer, size_t size);
        bool alloc_dpp_configuration_object(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_dpp_configuration_object = nullptr;
        size_t m_dpp_configuration_object_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVBSSCONFIGURATIONRESPONSE_H_
