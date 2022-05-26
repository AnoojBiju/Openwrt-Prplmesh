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

#include <tlvf/wfa_map/tlv1905EncapDpp.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlv1905EncapDpp::tlv1905EncapDpp(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlv1905EncapDpp::tlv1905EncapDpp(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlv1905EncapDpp::~tlv1905EncapDpp() {
}
const eTlvTypeMap& tlv1905EncapDpp::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlv1905EncapDpp::length() {
    return (const uint16_t&)(*m_length);
}

tlv1905EncapDpp::sFlags& tlv1905EncapDpp::frame_flags() {
    return (sFlags&)(*m_frame_flags);
}

bool tlv1905EncapDpp::alloc_dest_sta_mac() {
    if (m_dest_sta_mac_allocated) {
        LOG(ERROR) << "dest_sta_mac already allocated!";
        return false;
    }
    size_t len = sizeof(sMacAddr);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_dest_sta_mac;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_frame_type = (eFrameType *)((uint8_t *)(m_frame_type) + len);
    m_encapsulated_frame_length = (uint16_t *)((uint8_t *)(m_encapsulated_frame_length) + len);
    m_encapsulated_frame = (uint8_t *)((uint8_t *)(m_encapsulated_frame) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    m_dest_sta_mac_allocated = true;
    return true;
}

sMacAddr* tlv1905EncapDpp::dest_sta_mac() {
    if (!m_frame_flags || !(m_frame_flags->enrollee_mac_address_present)) {
        TLVF_LOG(ERROR) << "dest_sta_mac requested but condition not met: m_frame_flags->enrollee_mac_address_present";
        return nullptr;
    }
    return (sMacAddr*)(m_dest_sta_mac);
}

bool tlv1905EncapDpp::set_dest_sta_mac(const sMacAddr dest_sta_mac) {
    if (!m_dest_sta_mac_allocated && !alloc_dest_sta_mac()) {
        LOG(ERROR) << "Could not allocate dest_sta_mac!";
        return false;
    }
    *m_dest_sta_mac = dest_sta_mac;
    return true;
}

tlv1905EncapDpp::eFrameType& tlv1905EncapDpp::frame_type() {
    return (eFrameType&)(*m_frame_type);
}

uint16_t& tlv1905EncapDpp::encapsulated_frame_length() {
    return (uint16_t&)(*m_encapsulated_frame_length);
}

uint8_t* tlv1905EncapDpp::encapsulated_frame(size_t idx) {
    if ( (m_encapsulated_frame_idx__ == 0) || (m_encapsulated_frame_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_encapsulated_frame[idx]);
}

bool tlv1905EncapDpp::set_encapsulated_frame(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_encapsulated_frame received a null pointer.";
        return false;
    }
    if (m_encapsulated_frame_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_encapsulated_frame was already allocated!";
        return false;
    }
    if (!alloc_encapsulated_frame(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_encapsulated_frame);
    return true;
}
bool tlv1905EncapDpp::alloc_encapsulated_frame(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list encapsulated_frame, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_encapsulated_frame[*m_encapsulated_frame_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_encapsulated_frame_idx__ += count;
    *m_encapsulated_frame_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void tlv1905EncapDpp::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_frame_flags->struct_swap();
    if (m_frame_flags->enrollee_mac_address_present) {
        m_dest_sta_mac->struct_swap();
    }
    tlvf_swap(8*sizeof(eFrameType), reinterpret_cast<uint8_t*>(m_frame_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_encapsulated_frame_length));
}

bool tlv1905EncapDpp::finalize()
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

size_t tlv1905EncapDpp::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sFlags); // frame_flags
    class_size += sizeof(eFrameType); // frame_type
    class_size += sizeof(uint16_t); // encapsulated_frame_length
    return class_size;
}

bool tlv1905EncapDpp::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_1905_ENCAP_DPP;
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
    m_frame_flags = reinterpret_cast<sFlags*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags); }
    if (!m_parse__) { m_frame_flags->struct_init(); }
    m_dest_sta_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if ((m_frame_flags->enrollee_mac_address_present) && !buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_dest_sta_mac->struct_init(); }
    m_frame_type = reinterpret_cast<eFrameType*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eFrameType))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eFrameType) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eFrameType); }
    m_encapsulated_frame_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_encapsulated_frame_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_encapsulated_frame = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    uint16_t encapsulated_frame_length = *m_encapsulated_frame_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&encapsulated_frame_length)); }
    m_encapsulated_frame_idx__ = encapsulated_frame_length;
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (encapsulated_frame_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (encapsulated_frame_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_1905_ENCAP_DPP) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_1905_ENCAP_DPP) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


