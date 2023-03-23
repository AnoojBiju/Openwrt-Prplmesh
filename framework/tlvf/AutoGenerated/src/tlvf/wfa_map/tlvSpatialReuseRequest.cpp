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

#include <tlvf/wfa_map/tlvSpatialReuseRequest.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvSpatialReuseRequest::tlvSpatialReuseRequest(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvSpatialReuseRequest::tlvSpatialReuseRequest(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvSpatialReuseRequest::~tlvSpatialReuseRequest() {
}
const eTlvTypeMap& tlvSpatialReuseRequest::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvSpatialReuseRequest::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvSpatialReuseRequest::radio_uid() {
    return (sMacAddr&)(*m_radio_uid);
}

tlvSpatialReuseRequest::sFlags1& tlvSpatialReuseRequest::flags1() {
    return (sFlags1&)(*m_flags1);
}

tlvSpatialReuseRequest::sFlags2& tlvSpatialReuseRequest::flags2() {
    return (sFlags2&)(*m_flags2);
}

uint8_t& tlvSpatialReuseRequest::non_srg_obsspd_max_offset() {
    return (uint8_t&)(*m_non_srg_obsspd_max_offset);
}

uint8_t& tlvSpatialReuseRequest::srg_obsspd_min_offset() {
    return (uint8_t&)(*m_srg_obsspd_min_offset);
}

uint8_t& tlvSpatialReuseRequest::srg_obsspd_max_offset() {
    return (uint8_t&)(*m_srg_obsspd_max_offset);
}

uint64_t& tlvSpatialReuseRequest::srg_bss_color_bitmap() {
    return (uint64_t&)(*m_srg_bss_color_bitmap);
}

uint64_t& tlvSpatialReuseRequest::srg_partial_bssid_bitmap() {
    return (uint64_t&)(*m_srg_partial_bssid_bitmap);
}

uint16_t& tlvSpatialReuseRequest::reserved() {
    return (uint16_t&)(*m_reserved);
}

void tlvSpatialReuseRequest::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_radio_uid->struct_swap();
    m_flags1->struct_swap();
    m_flags2->struct_swap();
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_srg_bss_color_bitmap));
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_srg_partial_bssid_bitmap));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_reserved));
}

bool tlvSpatialReuseRequest::finalize()
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

size_t tlvSpatialReuseRequest::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // radio_uid
    class_size += sizeof(sFlags1); // flags1
    class_size += sizeof(sFlags2); // flags2
    class_size += sizeof(uint8_t); // non_srg_obsspd_max_offset
    class_size += sizeof(uint8_t); // srg_obsspd_min_offset
    class_size += sizeof(uint8_t); // srg_obsspd_max_offset
    class_size += sizeof(uint64_t); // srg_bss_color_bitmap
    class_size += sizeof(uint64_t); // srg_partial_bssid_bitmap
    class_size += sizeof(uint16_t); // reserved
    return class_size;
}

bool tlvSpatialReuseRequest::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_SPATIAL_REUSE_REQUEST;
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
    m_non_srg_obsspd_max_offset = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_srg_obsspd_min_offset = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_srg_obsspd_max_offset = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_srg_bss_color_bitmap = reinterpret_cast<uint64_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint64_t); }
    m_srg_partial_bssid_bitmap = reinterpret_cast<uint64_t*>(m_buff_ptr__);
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
        if (*m_type != eTlvTypeMap::TLV_SPATIAL_REUSE_REQUEST) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_SPATIAL_REUSE_REQUEST) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


