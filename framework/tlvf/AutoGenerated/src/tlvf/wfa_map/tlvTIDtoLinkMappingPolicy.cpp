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

sMacAddr& tlvTIDtoLinkMappingPolicy::MLD_MAC_Addr() {
    return (sMacAddr&)(*m_MLD_MAC_Addr);
}

uint8_t* tlvTIDtoLinkMappingPolicy::reserved_1(size_t idx) {
    if ( (m_reserved_1_idx__ == 0) || (m_reserved_1_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_1[idx]);
}

bool tlvTIDtoLinkMappingPolicy::set_reserved_1(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_1 received a null pointer.";
        return false;
    }
    if (size > 22) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_1);
    return true;
}
uint16_t& tlvTIDtoLinkMappingPolicy::num_Mapping() {
    return (uint16_t&)(*m_num_Mapping);
}

std::tuple<bool, cNumTIDtoLinks&> tlvTIDtoLinkMappingPolicy::numTIDtoLinkMappings(size_t idx) {
    bool ret_success = ( (m_numTIDtoLinkMappings_idx__ > 0) && (m_numTIDtoLinkMappings_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_numTIDtoLinkMappings_vector[ret_idx]));
}

std::shared_ptr<cNumTIDtoLinks> tlvTIDtoLinkMappingPolicy::create_numTIDtoLinkMappings() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list numTIDtoLinkMappings, abort!";
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
    uint8_t *src = (uint8_t *)m_numTIDtoLinkMappings;
    if (m_numTIDtoLinkMappings_idx__ > 0) {
        src = (uint8_t *)m_numTIDtoLinkMappings_vector[m_numTIDtoLinkMappings_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cNumTIDtoLinks>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvTIDtoLinkMappingPolicy::add_numTIDtoLinkMappings(std::shared_ptr<cNumTIDtoLinks> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_numTIDtoLinkMappings was called before add_numTIDtoLinkMappings";
        return false;
    }
    uint8_t *src = (uint8_t *)m_numTIDtoLinkMappings;
    if (m_numTIDtoLinkMappings_idx__ > 0) {
        src = (uint8_t *)m_numTIDtoLinkMappings_vector[m_numTIDtoLinkMappings_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_numTIDtoLinkMappings_idx__++;
    if (!m_parse__) { (*m_num_Mapping)++; }
    size_t len = ptr->getLen();
    m_numTIDtoLinkMappings_vector.push_back(ptr);
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
    m_MLD_MAC_Addr->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_num_Mapping));
    for (size_t i = 0; i < m_numTIDtoLinkMappings_idx__; i++){
        std::get<1>(numTIDtoLinkMappings(i)).class_swap();
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
    class_size += sizeof(sMacAddr); // MLD_MAC_Addr
    class_size += 22 * sizeof(uint8_t); // reserved_1
    class_size += sizeof(uint16_t); // num_Mapping
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
    m_MLD_MAC_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_MLD_MAC_Addr->struct_init(); }
    m_reserved_1 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (22))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (22) << ") Failed!";
        return false;
    }
    m_reserved_1_idx__  = 22;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 22); }
    }
    m_num_Mapping = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_numTIDtoLinkMappings = reinterpret_cast<cNumTIDtoLinks*>(m_buff_ptr__);
    uint16_t num_Mapping = *m_num_Mapping;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&num_Mapping)); }
    m_numTIDtoLinkMappings_idx__ = 0;
    for (size_t i = 0; i < num_Mapping; i++) {
        auto numTIDtoLinkMappings = create_numTIDtoLinkMappings();
        if (!numTIDtoLinkMappings || !numTIDtoLinkMappings->isInitialized()) {
            TLVF_LOG(ERROR) << "create_numTIDtoLinkMappings() failed";
            return false;
        }
        if (!add_numTIDtoLinkMappings(numTIDtoLinkMappings)) {
            TLVF_LOG(ERROR) << "add_numTIDtoLinkMappings() failed";
            return false;
        }
        // swap back since numTIDtoLinkMappings will be swapped as part of the whole class swap
        numTIDtoLinkMappings->class_swap();
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

sMacAddr& cNumTIDtoLinks::STA_MLD_MAC_Addr() {
    return (sMacAddr&)(*m_STA_MLD_MAC_Addr);
}

uint8_t& cNumTIDtoLinks::link_Mapping_Presence_Indicator() {
    return (uint8_t&)(*m_link_Mapping_Presence_Indicator);
}

uint8_t* cNumTIDtoLinks::expected_Duration(size_t idx) {
    if ( (m_expected_Duration_idx__ == 0) || (m_expected_Duration_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_expected_Duration[idx]);
}

bool cNumTIDtoLinks::set_expected_Duration(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_expected_Duration received a null pointer.";
        return false;
    }
    if (size > 3) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_expected_Duration);
    return true;
}
uint16_t* cNumTIDtoLinks::TIDtoLinkMappings(size_t idx) {
    if ( (m_TIDtoLinkMappings_idx__ == 0) || (m_TIDtoLinkMappings_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_TIDtoLinkMappings[idx]);
}

bool cNumTIDtoLinks::alloc_TIDtoLinkMappings(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list TIDtoLinkMappings, abort!";
        return false;
    }
    size_t len = sizeof(uint16_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_TIDtoLinkMappings[*m_link_Mapping_Presence_Indicator];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_reserved_4 = (uint8_t *)((uint8_t *)(m_reserved_4) + len);
    m_TIDtoLinkMappings_idx__ += count;
    *m_link_Mapping_Presence_Indicator += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

uint8_t* cNumTIDtoLinks::reserved_4(size_t idx) {
    if ( (m_reserved_4_idx__ == 0) || (m_reserved_4_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_4[idx]);
}

bool cNumTIDtoLinks::set_reserved_4(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_4 received a null pointer.";
        return false;
    }
    if (size > 7) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_4);
    return true;
}
void cNumTIDtoLinks::class_swap()
{
    m_flags->struct_swap();
    m_STA_MLD_MAC_Addr->struct_swap();
    for (size_t i = 0; i < m_TIDtoLinkMappings_idx__; i++){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&m_TIDtoLinkMappings[i]));
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
    class_size += sizeof(sMacAddr); // STA_MLD_MAC_Addr
    class_size += sizeof(uint8_t); // link_Mapping_Presence_Indicator
    class_size += 3 * sizeof(uint8_t); // expected_Duration
    class_size += 7 * sizeof(uint8_t); // reserved_4
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
    m_STA_MLD_MAC_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_STA_MLD_MAC_Addr->struct_init(); }
    m_link_Mapping_Presence_Indicator = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_link_Mapping_Presence_Indicator = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_expected_Duration = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (3))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (3) << ") Failed!";
        return false;
    }
    m_expected_Duration_idx__  = 3;
    m_TIDtoLinkMappings = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    uint8_t link_Mapping_Presence_Indicator = *m_link_Mapping_Presence_Indicator;
    m_TIDtoLinkMappings_idx__ = link_Mapping_Presence_Indicator;
    if (!buffPtrIncrementSafe(sizeof(uint16_t) * (link_Mapping_Presence_Indicator))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) * (link_Mapping_Presence_Indicator) << ") Failed!";
        return false;
    }
    m_reserved_4 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (7))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (7) << ") Failed!";
        return false;
    }
    m_reserved_4_idx__  = 7;
    if (m_parse__) { class_swap(); }
    return true;
}


