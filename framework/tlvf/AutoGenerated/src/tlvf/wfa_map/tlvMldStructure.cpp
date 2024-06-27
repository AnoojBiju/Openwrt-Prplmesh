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

#include <tlvf/wfa_map/tlvMldStructure.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvMldStructure::tlvMldStructure(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvMldStructure::tlvMldStructure(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvMldStructure::~tlvMldStructure() {
}
const eTlvTypeMap& tlvMldStructure::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvMldStructure::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvMldStructure::mld_mac_addr() {
    return (sMacAddr&)(*m_mld_mac_addr);
}

uint8_t* tlvMldStructure::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvMldStructure::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 25) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
uint8_t& tlvMldStructure::affliated_mac_length() {
    return (uint8_t&)(*m_affliated_mac_length);
}

std::tuple<bool, tlvMldStructure::sNumaffliated&> tlvMldStructure::num_affliated(size_t idx) {
    bool ret_success = ( (m_num_affliated_idx__ > 0) && (m_num_affliated_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_num_affliated[ret_idx]);
}

bool tlvMldStructure::alloc_num_affliated(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list num_affliated, abort!";
        return false;
    }
    size_t len = sizeof(sNumaffliated) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_num_affliated[*m_affliated_mac_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_affliated_idx__ += count;
    *m_affliated_mac_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    if (!m_parse__) { 
        for (size_t i = m_num_affliated_idx__ - count; i < m_num_affliated_idx__; i++) { m_num_affliated[i].struct_init(); }
    }
    return true;
}

void tlvMldStructure::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_mld_mac_addr->struct_swap();
    for (size_t i = 0; i < m_num_affliated_idx__; i++){
        m_num_affliated[i].struct_swap();
    }
}

bool tlvMldStructure::finalize()
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

size_t tlvMldStructure::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // mld_mac_addr
    class_size += 25 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint8_t); // affliated_mac_length
    return class_size;
}

bool tlvMldStructure::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_MLD_STRUCTURE;
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
    m_mld_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_mld_mac_addr->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (25))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (25) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 25;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 25); }
    }
    m_affliated_mac_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_affliated_mac_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_num_affliated = reinterpret_cast<sNumaffliated*>(m_buff_ptr__);
    uint8_t affliated_mac_length = *m_affliated_mac_length;
    m_num_affliated_idx__ = affliated_mac_length;
    if (!buffPtrIncrementSafe(sizeof(sNumaffliated) * (affliated_mac_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sNumaffliated) * (affliated_mac_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_MLD_STRUCTURE) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_MLD_STRUCTURE) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


