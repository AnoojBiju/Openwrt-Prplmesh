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

#ifndef _TLVF_WFA_MAP_TLVDPPBOOTSTRAPPINGURINOTIFICATION_H_
#define _TLVF_WFA_MAP_TLVDPPBOOTSTRAPPINGURINOTIFICATION_H_

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


class tlvDppBootstrappingUriNotification : public BaseClass
{
    public:
        tlvDppBootstrappingUriNotification(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvDppBootstrappingUriNotification(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvDppBootstrappingUriNotification();

        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& ruid();
        //MAC Address of Local Interface (equal to BSSID) operating on the radio, on which the URI was
        //received during PBC onboarding.
        sMacAddr& bssid();
        //MAC Address of backhaul STA from which the URI was received during PBC onboarding.
        sMacAddr& backhaul_sta_address();
        //DPP URI received during PBC onboarding (note: format of URI is specified in section 5.2.1 of 
        //Wi-Fi Easy Connect Specification.
        size_t dpp_uri_length() { return m_dpp_uri_idx__ * sizeof(char); }
        std::string dpp_uri_str();
        char* dpp_uri(size_t length = 0);
        bool set_dpp_uri(const std::string& str);
        bool set_dpp_uri(const char buffer[], size_t size);
        bool alloc_dpp_uri(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_ruid = nullptr;
        sMacAddr* m_bssid = nullptr;
        sMacAddr* m_backhaul_sta_address = nullptr;
        char* m_dpp_uri = nullptr;
        size_t m_dpp_uri_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVDPPBOOTSTRAPPINGURINOTIFICATION_H_
