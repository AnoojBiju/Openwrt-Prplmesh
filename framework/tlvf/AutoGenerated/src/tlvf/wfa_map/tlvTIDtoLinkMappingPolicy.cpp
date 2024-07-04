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

#include <tlvf/wfa_map/tlvTIDtoLinkMappingPolicy.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvTIDtoLinkMappingPolicy::tlvTIDtoLinkMappingPolicy(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvTIDtoLinkMappingPolicy::tlvTIDtoLinkMappingPolicy(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvTIDtoLinkMappingPolicy::~tlvTIDtoLinkMappingPolicy() {
}
const eTlvTypeMap& tlvTIDtoLinkMappingPolicy::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvTIDtoLinkMappingPolicy::length() {
    return (const uint16_t&)(*m_length);
}

tlvTIDtoLinkMappingPolicy::sFlags2& tlvTIDtoLinkMappingPolicy::flags() {
    return (sFlags2&)(*m_flags);
}

sMacAddr& tlvTIDtoLinkMappingPolicy::mld_mac_Addr() {
    return (sMacAddr&)(*m_mld_mac_Addr);
}

uint8_t* tlvTIDtoLinkMappingPolicy::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvTIDtoLinkMappingPolicy::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 22) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
uint16_t& tlvTIDtoLinkMappingPolicy::num_mapping() {
    return (uint16_t&)(*m_num_mapping);
}

std::tuple<bool, cNumTIDtoLinks&> tlvTIDtoLinkMappingPolicy::num_tid_to_link_mappings(size_t idx) {
    bool ret_success = ( (m_num_tid_to_link_mappings_idx__ > 0) && (m_num_tid_to_link_mappings_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_num_tid_to_link_mappings_vector[ret_idx]));
}

std::shared_ptr<cNumTIDtoLinks> tlvTIDtoLinkMappingPolicy::create_num_tid_to_link_mappings() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list num_tid_to_link_mappings, abort!";
        return nullptr;
    }
    size_t len = cNumTIDtoLinks::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 0;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_num_tid_to_link_mappings;
    if (m_num_tid_to_link_mappings_idx__ > 0) {
        src = (uint8_t *)m_num_tid_to_link_mappings_vector[m_num_tid_to_link_mappings_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cNumTIDtoLinks>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvTIDtoLinkMappingPolicy::add_num_tid_to_link_mappings(std::shared_ptr<cNumTIDtoLinks> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_num_tid_to_link_mappings was called before add_num_tid_to_link_mappings";
        return false;
    }
    uint8_t *src = (uint8_t *)m_num_tid_to_link_mappings;
    if (m_num_tid_to_link_mappings_idx__ > 0) {
        src = (uint8_t *)m_num_tid_to_link_mappings_vector[m_num_tid_to_link_mappings_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_num_tid_to_link_mappings_idx__++;
    if (!m_parse__) { (*m_num_mapping)++; }
    size_t len = ptr->getLen();
    m_num_tid_to_link_mappings_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvTIDtoLinkMappingPolicy::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_flags->struct_swap();
    m_mld_mac_Addr->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_num_mapping));
    for (size_t i = 0; i < m_num_tid_to_link_mappings_idx__; i++){
        std::get<1>(num_tid_to_link_mappings(i)).class_swap();
    }
}

bool tlvTIDtoLinkMappingPolicy::finalize()
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

size_t tlvTIDtoLinkMappingPolicy::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sFlags2); // flags
    class_size += sizeof(sMacAddr); // mld_mac_Addr
    class_size += 22 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint16_t); // num_mapping
    return class_size;
}

bool tlvTIDtoLinkMappingPolicy::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_TID_TO_LINK_MAPPING_POLICY;
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
    m_flags = reinterpret_cast<sFlags2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags2); }
    if (!m_parse__) { m_flags->struct_init(); }
    m_mld_mac_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_mld_mac_Addr->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (22))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (22) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 22;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 22); }
    }
    m_num_mapping = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_num_tid_to_link_mappings = reinterpret_cast<cNumTIDtoLinks*>(m_buff_ptr__);
    uint16_t num_mapping = *m_num_mapping;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&num_mapping)); }
    m_num_tid_to_link_mappings_idx__ = 0;
    for (size_t i = 0; i < num_mapping; i++) {
        auto num_tid_to_link_mappings = create_num_tid_to_link_mappings();
        if (!num_tid_to_link_mappings || !num_tid_to_link_mappings->isInitialized()) {
            TLVF_LOG(ERROR) << "create_num_tid_to_link_mappings() failed";
            return false;
        }
        if (!add_num_tid_to_link_mappings(num_tid_to_link_mappings)) {
            TLVF_LOG(ERROR) << "add_num_tid_to_link_mappings() failed";
            return false;
        }
        // swap back since num_tid_to_link_mappings will be swapped as part of the whole class swap
        num_tid_to_link_mappings->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_TID_TO_LINK_MAPPING_POLICY) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_TID_TO_LINK_MAPPING_POLICY) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cNumTIDtoLinks::cNumTIDtoLinks(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cNumTIDtoLinks::cNumTIDtoLinks(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cNumTIDtoLinks::~cNumTIDtoLinks() {
}
cNumTIDtoLinks::sFlags4& cNumTIDtoLinks::flags() {
    return (sFlags4&)(*m_flags);
}

sMacAddr& cNumTIDtoLinks::sta_mld_mac_addr() {
    return (sMacAddr&)(*m_sta_mld_mac_addr);
}

uint8_t& cNumTIDtoLinks::link_mapping_presence_indicator() {
    return (uint8_t&)(*m_link_mapping_presence_indicator);
}

uint8_t* cNumTIDtoLinks::expected_duration(size_t idx) {
    if ( (m_expected_duration_idx__ == 0) || (m_expected_duration_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_expected_duration[idx]);
}

bool cNumTIDtoLinks::set_expected_duration(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_expected_duration received a null pointer.";
        return false;
    }
    if (size > 3) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_expected_duration);
    return true;
}
uint16_t* cNumTIDtoLinks::tid_to_link_mappings(size_t idx) {
    if ( (m_tid_to_link_mappings_idx__ == 0) || (m_tid_to_link_mappings_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_tid_to_link_mappings[idx]);
}

bool cNumTIDtoLinks::alloc_tid_to_link_mappings(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list tid_to_link_mappings, abort!";
        return false;
    }
    size_t len = sizeof(uint16_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_tid_to_link_mappings[*m_link_mapping_presence_indicator];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len);
    m_tid_to_link_mappings_idx__ += count;
    *m_link_mapping_presence_indicator += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

uint8_t* cNumTIDtoLinks::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cNumTIDtoLinks::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 7) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
void cNumTIDtoLinks::class_swap()
{
    m_flags->struct_swap();
    m_sta_mld_mac_addr->struct_swap();
    for (size_t i = 0; i < m_tid_to_link_mappings_idx__; i++){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&m_tid_to_link_mappings[i]));
    }
}

bool cNumTIDtoLinks::finalize()
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
    }
    class_swap();
    m_finalized__ = true;
    return true;
}

size_t cNumTIDtoLinks::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sFlags4); // flags
    class_size += sizeof(sMacAddr); // sta_mld_mac_addr
    class_size += sizeof(uint8_t); // link_mapping_presence_indicator
    class_size += 3 * sizeof(uint8_t); // expected_duration
    class_size += 7 * sizeof(uint8_t); // reserved
    return class_size;
}

bool cNumTIDtoLinks::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_flags = reinterpret_cast<sFlags4*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags4))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags4) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    m_sta_mld_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_sta_mld_mac_addr->struct_init(); }
    m_link_mapping_presence_indicator = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_link_mapping_presence_indicator = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_expected_duration = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (3))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (3) << ") Failed!";
        return false;
    }
    m_expected_duration_idx__  = 3;
    m_tid_to_link_mappings = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    uint8_t link_mapping_presence_indicator = *m_link_mapping_presence_indicator;
    m_tid_to_link_mappings_idx__ = link_mapping_presence_indicator;
    if (!buffPtrIncrementSafe(sizeof(uint16_t) * (link_mapping_presence_indicator))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) * (link_mapping_presence_indicator) << ") Failed!";
        return false;
    }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (7))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (7) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 7;
    if (m_parse__) { class_swap(); }
    return true;
}


