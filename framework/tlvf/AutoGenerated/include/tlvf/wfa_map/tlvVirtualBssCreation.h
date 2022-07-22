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

#ifndef _TLVF_WFA_MAP_TLVVIRTUALBSSCREATION_H_
#define _TLVF_WFA_MAP_TLVVIRTUALBSSCREATION_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tuple>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/wfa_map/eVirtualBssSubtype.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class VirtualBssCreation : public BaseClass
{
    public:
        VirtualBssCreation(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit VirtualBssCreation(std::shared_ptr<BaseClass> base, bool parse = false);
        ~VirtualBssCreation();

        const eTlvTypeMap& type();
        const uint16_t& length();
        const eVirtualBssSubtype& subtype();
        sMacAddr& radio_uid();
        sMacAddr& bssid();
        uint16_t& ssid_length();
        std::string ssid_str();
        char* ssid(size_t length = 0);
        bool set_ssid(const std::string& str);
        bool set_ssid(const char buffer[], size_t size);
        bool alloc_ssid(size_t count = 1);
        //0 indicates that the WPA2 or SAE Pass is not present
        uint16_t& pass_length();
        std::string pass_str();
        char* pass(size_t length = 0);
        bool set_pass(const std::string& str);
        bool set_pass(const char buffer[], size_t size);
        bool alloc_pass(size_t count = 1);
        //0 indicates that DPP Connector is not present
        uint16_t& dpp_connector_length();
        std::string dpp_connector_str();
        char* dpp_connector(size_t length = 0);
        bool set_dpp_connector(const std::string& str);
        bool set_dpp_connector(const char buffer[], size_t size);
        bool alloc_dpp_connector(size_t count = 1);
        sMacAddr& client_mac();
        //If 1, client is already associated, 0 if client is not yet
        //associated. If this flag is 1 then the security context fields
        //below are populated. If 0, then the security fields below are
        //filled in with 0s.
        uint8_t& client_assoc();
        uint16_t& key_length();
        uint8_t* ptk(size_t idx = 0);
        bool set_ptk(const void* buffer, size_t size);
        bool alloc_ptk(size_t count = 1);
        uint64_t& tx_packet_num();
        uint16_t& group_key_length();
        uint8_t* gtk(size_t idx = 0);
        bool set_gtk(const void* buffer, size_t size);
        bool alloc_gtk(size_t count = 1);
        uint64_t& group_tx_packet_num();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eVirtualBssSubtype* m_subtype = nullptr;
        sMacAddr* m_radio_uid = nullptr;
        sMacAddr* m_bssid = nullptr;
        uint16_t* m_ssid_length = nullptr;
        char* m_ssid = nullptr;
        size_t m_ssid_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint16_t* m_pass_length = nullptr;
        char* m_pass = nullptr;
        size_t m_pass_idx__ = 0;
        uint16_t* m_dpp_connector_length = nullptr;
        char* m_dpp_connector = nullptr;
        size_t m_dpp_connector_idx__ = 0;
        sMacAddr* m_client_mac = nullptr;
        uint8_t* m_client_assoc = nullptr;
        uint16_t* m_key_length = nullptr;
        uint8_t* m_ptk = nullptr;
        size_t m_ptk_idx__ = 0;
        uint64_t* m_tx_packet_num = nullptr;
        uint16_t* m_group_key_length = nullptr;
        uint8_t* m_gtk = nullptr;
        size_t m_gtk_idx__ = 0;
        uint64_t* m_group_tx_packet_num = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVVIRTUALBSSCREATION_H_
