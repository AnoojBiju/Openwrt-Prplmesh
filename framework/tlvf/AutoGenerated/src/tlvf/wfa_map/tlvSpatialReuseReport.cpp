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

#include <tlvf/wfa_map/tlvSpatialReuseReport.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvSpatialReuseReport::tlvSpatialReuseReport(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvSpatialReuseReport::tlvSpatialReuseReport(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvSpatialReuseReport::~tlvSpatialReuseReport() {
}
const eTlvTypeMap& tlvSpatialReuseReport::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvSpatialReuseReport::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvSpatialReuseReport::radio_uid() {
    return (sMacAddr&)(*m_radio_uid);
}

tlvSpatialReuseReport::sFlags1& tlvSpatialReuseReport::flags1() {
    return (sFlags1&)(*m_flags1);
}

tlvSpatialReuseReport::sFlags2& tlvSpatialReuseReport::flags2() {
    return (sFlags2&)(*m_flags2);
}

uint8_t& tlvSpatialReuseReport::Non_SRG_obsspd_max_offset() {
    return (uint8_t&)(*m_Non_SRG_obsspd_max_offset);
}

uint8_t& tlvSpatialReuseReport::SRG_obsspd_min_offset() {
    return (uint8_t&)(*m_SRG_obsspd_min_offset);
}

uint8_t& tlvSpatialReuseReport::SRG_obsspd_max_offset() {
    return (uint8_t&)(*m_SRG_obsspd_max_offset);
}

uint64_t& tlvSpatialReuseReport::SRG_bss_color_bitmap() {
    return (uint64_t&)(*m_SRG_bss_color_bitmap);
}

uint64_t& tlvSpatialReuseReport::SRG_partial_bssid_bitmap() {
    return (uint64_t&)(*m_SRG_partial_bssid_bitmap);
}

uint64_t& tlvSpatialReuseReport::Neighbor_bss_color_in_use_bitmap() {
    return (uint64_t&)(*m_Neighbor_bss_color_in_use_bitmap);
}

uint16_t& tlvSpatialReuseReport::reserved() {
    return (uint16_t&)(*m_reserved);
}

void tlvSpatialReuseReport::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_radio_uid->struct_swap();
    m_flags1->struct_swap();
    m_flags2->struct_swap();
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_SRG_bss_color_bitmap));
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_SRG_partial_bssid_bitmap));
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_Neighbor_bss_color_in_use_bitmap));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_reserved));
}

bool tlvSpatialReuseReport::finalize()
{
    if (m_parse__) {
        TLVF_LOG(DEBUG) << "finalize() called but m_parse__ is set";
        return true;
    }
    if (m_finalized__) {
        TLVF_LOG(DEBUG) << "finalize() called for already finalized class";
        return true;
    }
    if (!isPostInitSucceeded()) {
        TLVF_LOG(ERROR) << "post init check failed";
        return false;
    }
    if (m_inner__) {
        if (!m_inner__->finalize()) {
            TLVF_LOG(ERROR) << "m_inner__->finalize() failed";
            return false;
        }
        auto tailroom = m_inner__->getMessageBuffLength() - m_inner__->getMessageLength();
        m_buff_ptr__ -= tailroom;
        *m_length -= tailroom;
    }
    class_swap();
    m_finalized__ = true;
    return true;
}

size_t tlvSpatialReuseReport::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // radio_uid
    class_size += sizeof(sFlags1); // flags1
    class_size += sizeof(sFlags2); // flags2
    class_size += sizeof(uint8_t); // Non_SRG_obsspd_max_offset
    class_size += sizeof(uint8_t); // SRG_obsspd_min_offset
    class_size += sizeof(uint8_t); // SRG_obsspd_max_offset
    class_size += sizeof(uint64_t); // SRG_bss_color_bitmap
    class_size += sizeof(uint64_t); // SRG_partial_bssid_bitmap
    class_size += sizeof(uint64_t); // Neighbor_bss_color_in_use_bitmap
    class_size += sizeof(uint16_t); // reserved
    return class_size;
}

bool tlvSpatialReuseReport::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_SPATIAL_REUSE_REPORT;
    if (!buffPtrIncrementSafe(sizeof(eTlvTypeMap))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eTlvTypeMap) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_radio_uid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_radio_uid->struct_init(); }
    m_flags1 = reinterpret_cast<sFlags1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags1) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags1); }
    if (!m_parse__) { m_flags1->struct_init(); }
    m_flags2 = reinterpret_cast<sFlags2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags2); }
    if (!m_parse__) { m_flags2->struct_init(); }
    m_Non_SRG_obsspd_max_offset = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_Non_SRG_obsspd_max_offset = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_SRG_obsspd_min_offset = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_SRG_obsspd_min_offset = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_SRG_obsspd_max_offset = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_SRG_obsspd_max_offset = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_SRG_bss_color_bitmap = reinterpret_cast<uint64_t*>(m_buff_ptr__);
    if (!m_parse__) *m_SRG_bss_color_bitmap = 0;
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint64_t); }
    m_SRG_partial_bssid_bitmap = reinterpret_cast<uint64_t*>(m_buff_ptr__);
    if (!m_parse__) *m_SRG_partial_bssid_bitmap = 0;
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint64_t); }
    m_Neighbor_bss_color_in_use_bitmap = reinterpret_cast<uint64_t*>(m_buff_ptr__);
    if (!m_parse__) *m_Neighbor_bss_color_in_use_bitmap = 0;
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint64_t); }
    m_reserved = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_SPATIAL_REUSE_REPORT) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_SPATIAL_REUSE_REPORT) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


