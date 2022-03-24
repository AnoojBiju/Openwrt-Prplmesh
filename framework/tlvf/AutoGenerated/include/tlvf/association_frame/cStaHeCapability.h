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

#ifndef _TLVF_ASSOCIATION_FRAME_CSTAHECAPABILITY_H_
#define _TLVF_ASSOCIATION_FRAME_CSTAHECAPABILITY_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tuple>
#include <asm/byteorder.h>
#include "tlvf/association_frame/eElementID.h"
#include "tlvf/AssociationRequestFrame/assoc_frame_bitfields.h"
#include "tlvf/association_frame/eExtElementID.h"

namespace assoc_frame {


class cStaHeCapability : public BaseClass
{
    public:
        cStaHeCapability(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cStaHeCapability(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cStaHeCapability();

        typedef struct sStaHePhyCapInfoB1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved1 : 1;
            uint8_t bw_40_in_2_4 : 1;
            uint8_t bw_40_80_in_5 : 1;
            uint8_t bw_160_in_5 : 1;
            uint8_t bw_160_80p80_in_5 : 1;
            uint8_t tone_242_rus_in_2_4 : 1;
            uint8_t tone_242_rus_in_5 : 1;
            uint8_t reserved2 : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t reserved2 : 1;
            uint8_t tone_242_rus_in_5 : 1;
            uint8_t tone_242_rus_in_2_4 : 1;
            uint8_t bw_160_80p80_in_5 : 1;
            uint8_t bw_160_in_5 : 1;
            uint8_t bw_40_80_in_5 : 1;
            uint8_t bw_40_in_2_4 : 1;
            uint8_t reserved1 : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sStaHePhyCapInfoB1;
        
        eElementID& type();
        const uint8_t& length();
        eExtElementID& subtype();
        assoc_frame::sStaHeMacCapInfo1& mac_cap_info1();
        assoc_frame::sStaHeMacCapInfo2& mac_cap_info2();
        //First byte of the PHY Capabilities containing Supported Channel Width Set field
        sStaHePhyCapInfoB1& supported_channel_width_set();
        assoc_frame::sStaHePhyCapInfo1& phy_cap_info1();
        assoc_frame::sStaHePhyCapInfo2& phy_cap_info2();
        //RX HE MCS for channel width lower or equal to 80 MHz
        uint16_t& rx_mcs_le_80();
        //TX HE MCS for channel width lower or equal to 80 MHz
        uint16_t& tx_mcs_le_80();
        bool alloc_rx_mcs_160();
        uint16_t* rx_mcs_160();
        bool set_rx_mcs_160(const uint16_t rx_mcs_160);
        bool alloc_tx_mcs_160();
        uint16_t* tx_mcs_160();
        bool set_tx_mcs_160(const uint16_t tx_mcs_160);
        bool alloc_rx_mcs_80_80();
        uint16_t* rx_mcs_80_80();
        bool set_rx_mcs_80_80(const uint16_t rx_mcs_80_80);
        bool alloc_tx_mcs_80_80();
        uint16_t* tx_mcs_80_80();
        bool set_tx_mcs_80_80(const uint16_t tx_mcs_80_80);
        //PPE Thresholds determines the nominal packet padding value
        size_t ppe_thresholds_length() { return m_ppe_thresholds_idx__ * sizeof(uint8_t); }
        uint8_t* ppe_thresholds(size_t idx = 0);
        bool set_ppe_thresholds(const void* buffer, size_t size);
        bool alloc_ppe_thresholds(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eElementID* m_type = nullptr;
        uint8_t* m_length = nullptr;
        eExtElementID* m_subtype = nullptr;
        assoc_frame::sStaHeMacCapInfo1* m_mac_cap_info1 = nullptr;
        assoc_frame::sStaHeMacCapInfo2* m_mac_cap_info2 = nullptr;
        sStaHePhyCapInfoB1* m_supported_channel_width_set = nullptr;
        assoc_frame::sStaHePhyCapInfo1* m_phy_cap_info1 = nullptr;
        assoc_frame::sStaHePhyCapInfo2* m_phy_cap_info2 = nullptr;
        uint16_t* m_rx_mcs_le_80 = nullptr;
        uint16_t* m_tx_mcs_le_80 = nullptr;
        uint16_t* m_rx_mcs_160 = nullptr;
        bool m_rx_mcs_160_allocated = false;
        uint16_t* m_tx_mcs_160 = nullptr;
        bool m_tx_mcs_160_allocated = false;
        uint16_t* m_rx_mcs_80_80 = nullptr;
        bool m_rx_mcs_80_80_allocated = false;
        uint16_t* m_tx_mcs_80_80 = nullptr;
        bool m_tx_mcs_80_80_allocated = false;
        uint8_t* m_ppe_thresholds = nullptr;
        size_t m_ppe_thresholds_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: assoc_frame

#endif //_TLVF/ASSOCIATION_FRAME_CSTAHECAPABILITY_H_
