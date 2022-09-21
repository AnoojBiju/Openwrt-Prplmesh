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

#ifndef _TLVF_WFA_MAP_TLVAPWIFI6CAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVAPWIFI6CAPABILITIES_H_

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
#include <vector>
#include <asm/byteorder.h>

namespace wfa_map {

class cRole;

class tlvApWifi6Capabilities : public BaseClass
{
    public:
        tlvApWifi6Capabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvApWifi6Capabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvApWifi6Capabilities();

        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& radio_uid();
        uint8_t& number_of_roles();
        std::tuple<bool, cRole&> role(size_t idx);
        std::shared_ptr<cRole> create_role();
        bool add_role(std::shared_ptr<cRole> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_radio_uid = nullptr;
        uint8_t* m_number_of_roles = nullptr;
        cRole* m_role = nullptr;
        size_t m_role_idx__ = 0;
        std::vector<std::shared_ptr<cRole>> m_role_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cRole : public BaseClass
{
    public:
        cRole(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRole(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRole();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t mcs_nss_length : 4;
            uint8_t he_support_80_80mhz : 1;
            uint8_t he_support_160mhz : 1;
            uint8_t agent_role : 2;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t agent_role : 2;
            uint8_t he_support_160mhz : 1;
            uint8_t he_support_80_80mhz : 1;
            uint8_t mcs_nss_length : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags1;
        
        typedef struct sFlags2 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t dl_ofdma : 1;
            uint8_t ul_ofdma : 1;
            uint8_t ul_mu_mimo : 1;
            uint8_t beamformee_sts_greater_80mhz : 1;
            uint8_t beamformee_sts_less_80mhz : 1;
            uint8_t mu_Beamformer_status : 1;
            uint8_t su_beamformee : 1;
            uint8_t su_beamformer : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t su_beamformer : 1;
            uint8_t su_beamformee : 1;
            uint8_t mu_Beamformer_status : 1;
            uint8_t beamformee_sts_less_80mhz : 1;
            uint8_t beamformee_sts_greater_80mhz : 1;
            uint8_t ul_mu_mimo : 1;
            uint8_t ul_ofdma : 1;
            uint8_t dl_ofdma : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags2;
        
        typedef struct sFlags3 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t max_ul_mu_mimo_rx : 4;
            uint8_t max_dl_mu_mimo_tx : 4;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t max_dl_mu_mimo_tx : 4;
            uint8_t max_ul_mu_mimo_rx : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags3;
        
        typedef struct sFlags4 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t anticipated_channel_usage : 1;
            uint8_t spatial_reuse : 1;
            uint8_t twt_responder : 1;
            uint8_t twt_requester : 1;
            uint8_t mu_edca : 1;
            uint8_t multi_bssid : 1;
            uint8_t mu_rts : 1;
            uint8_t rts : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t rts : 1;
            uint8_t mu_rts : 1;
            uint8_t multi_bssid : 1;
            uint8_t mu_edca : 1;
            uint8_t twt_requester : 1;
            uint8_t twt_responder : 1;
            uint8_t spatial_reuse : 1;
            uint8_t anticipated_channel_usage : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags4;
        
        sFlags1& flags1();
        //MCS for channel width lower or equal to 80 MHz
        uint32_t& mcs_nss_80();
        bool alloc_mcs_nss_160();
        uint32_t* mcs_nss_160();
        bool set_mcs_nss_160(const uint32_t mcs_nss_160);
        bool alloc_mcs_nss_80_80();
        uint32_t* mcs_nss_80_80();
        bool set_mcs_nss_80_80(const uint32_t mcs_nss_80_80);
        sFlags2& flags2();
        sFlags3& flags3();
        uint8_t& max_dl_ofdma_tx();
        uint8_t& max_ul_ofdma_rx();
        sFlags4& flags4();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sFlags1* m_flags1 = nullptr;
        uint32_t* m_mcs_nss_80 = nullptr;
        uint32_t* m_mcs_nss_160 = nullptr;
        bool m_mcs_nss_160_allocated = false;
        uint32_t* m_mcs_nss_80_80 = nullptr;
        bool m_mcs_nss_80_80_allocated = false;
        sFlags2* m_flags2 = nullptr;
        sFlags3* m_flags3 = nullptr;
        uint8_t* m_max_dl_ofdma_tx = nullptr;
        uint8_t* m_max_ul_ofdma_rx = nullptr;
        sFlags4* m_flags4 = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAPWIFI6CAPABILITIES_H_
