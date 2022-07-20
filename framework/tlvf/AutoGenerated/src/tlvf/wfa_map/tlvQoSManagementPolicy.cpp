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

#include <tlvf/wfa_map/tlvQoSManagementPolicy.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvQoSManagementPolicy::tlvQoSManagementPolicy(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvQoSManagementPolicy::tlvQoSManagementPolicy(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvQoSManagementPolicy::~tlvQoSManagementPolicy() {
}
const eTlvTypeMap& tlvQoSManagementPolicy::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvQoSManagementPolicy::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvQoSManagementPolicy::mscs_disallowed_sta_length() {
    return (uint8_t&)(*m_mscs_disallowed_sta_length);
}

std::tuple<bool, sMacAddr&> tlvQoSManagementPolicy::mscs_disallowed_sta_list(size_t idx) {
    bool ret_success = ( (m_mscs_disallowed_sta_list_idx__ > 0) && (m_mscs_disallowed_sta_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_mscs_disallowed_sta_list[ret_idx]);
}

bool tlvQoSManagementPolicy::alloc_mscs_disallowed_sta_list(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list mscs_disallowed_sta_list, abort!";
        return false;
    }
    size_t len = sizeof(sMacAddr) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_mscs_disallowed_sta_list[*m_mscs_disallowed_sta_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_scs_disallowed_sta_length = (uint8_t *)((uint8_t *)(m_scs_disallowed_sta_length) + len);
    m_scs_disallowed_sta_list = (sMacAddr *)((uint8_t *)(m_scs_disallowed_sta_list) + len);
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len);
    m_mscs_disallowed_sta_list_idx__ += count;
    *m_mscs_disallowed_sta_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    if (!m_parse__) { 
        for (size_t i = m_mscs_disallowed_sta_list_idx__ - count; i < m_mscs_disallowed_sta_list_idx__; i++) { m_mscs_disallowed_sta_list[i].struct_init(); }
    }
    return true;
}

uint8_t& tlvQoSManagementPolicy::scs_disallowed_sta_length() {
    return (uint8_t&)(*m_scs_disallowed_sta_length);
}

std::tuple<bool, sMacAddr&> tlvQoSManagementPolicy::scs_disallowed_sta_list(size_t idx) {
    bool ret_success = ( (m_scs_disallowed_sta_list_idx__ > 0) && (m_scs_disallowed_sta_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_scs_disallowed_sta_list[ret_idx]);
}

bool tlvQoSManagementPolicy::alloc_scs_disallowed_sta_list(size_t count) {
    if (m_lock_order_counter__ > 1) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list scs_disallowed_sta_list, abort!";
        return false;
    }
    size_t len = sizeof(sMacAddr) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 1;
    uint8_t *src = (uint8_t *)&m_scs_disallowed_sta_list[*m_scs_disallowed_sta_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len);
    m_scs_disallowed_sta_list_idx__ += count;
    *m_scs_disallowed_sta_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    if (!m_parse__) { 
        for (size_t i = m_scs_disallowed_sta_list_idx__ - count; i < m_scs_disallowed_sta_list_idx__; i++) { m_scs_disallowed_sta_list[i].struct_init(); }
    }
    return true;
}

uint8_t* tlvQoSManagementPolicy::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvQoSManagementPolicy::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 20) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
void tlvQoSManagementPolicy::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_mscs_disallowed_sta_list_idx__; i++){
        m_mscs_disallowed_sta_list[i].struct_swap();
    }
    for (size_t i = 0; i < m_scs_disallowed_sta_list_idx__; i++){
        m_scs_disallowed_sta_list[i].struct_swap();
    }
}

bool tlvQoSManagementPolicy::finalize()
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

size_t tlvQoSManagementPolicy::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // mscs_disallowed_sta_length
    class_size += sizeof(uint8_t); // scs_disallowed_sta_length
    class_size += 20 * sizeof(uint8_t); // reserved
    return class_size;
}

bool tlvQoSManagementPolicy::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_QOS_MANAGEMENT_POLICY;
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
    m_mscs_disallowed_sta_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_mscs_disallowed_sta_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_mscs_disallowed_sta_list = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    uint8_t mscs_disallowed_sta_length = *m_mscs_disallowed_sta_length;
    m_mscs_disallowed_sta_list_idx__ = mscs_disallowed_sta_length;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr) * (mscs_disallowed_sta_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) * (mscs_disallowed_sta_length) << ") Failed!";
        return false;
    }
    m_scs_disallowed_sta_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_scs_disallowed_sta_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_scs_disallowed_sta_list = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    uint8_t scs_disallowed_sta_length = *m_scs_disallowed_sta_length;
    m_scs_disallowed_sta_list_idx__ = scs_disallowed_sta_length;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr) * (scs_disallowed_sta_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) * (scs_disallowed_sta_length) << ") Failed!";
        return false;
    }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (20))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (20) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 20;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 20); }
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_QOS_MANAGEMENT_POLICY) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_QOS_MANAGEMENT_POLICY) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


