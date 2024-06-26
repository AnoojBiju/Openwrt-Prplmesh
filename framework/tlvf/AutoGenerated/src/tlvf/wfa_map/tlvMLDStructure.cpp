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

#include <tlvf/wfa_map/tlvMLDStructure.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvMLDStructure::tlvMLDStructure(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvMLDStructure::tlvMLDStructure(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvMLDStructure::~tlvMLDStructure() {
}
const eTlvTypeMap& tlvMLDStructure::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvMLDStructure::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvMLDStructure::MLDMACAddr() {
    return (sMacAddr&)(*m_MLDMACAddr);
}

uint8_t* tlvMLDStructure::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvMLDStructure::set_reserved(const void* buffer, size_t size) {
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
uint8_t& tlvMLDStructure::Num_Affiliated() {
    return (uint8_t&)(*m_Num_Affiliated);
}

std::tuple<bool, cAffiliatedEntry&> tlvMLDStructure::AffiliatedEntries(size_t idx) {
    bool ret_success = ( (m_AffiliatedEntries_idx__ > 0) && (m_AffiliatedEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_AffiliatedEntries_vector[ret_idx]));
}

std::shared_ptr<cAffiliatedEntry> tlvMLDStructure::create_AffiliatedEntries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list AffiliatedEntries, abort!";
        return nullptr;
    }
    size_t len = cAffiliatedEntry::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_AffiliatedEntries;
    if (m_AffiliatedEntries_idx__ > 0) {
        src = (uint8_t *)m_AffiliatedEntries_vector[m_AffiliatedEntries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cAffiliatedEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvMLDStructure::add_AffiliatedEntries(std::shared_ptr<cAffiliatedEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_AffiliatedEntries was called before add_AffiliatedEntries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_AffiliatedEntries;
    if (m_AffiliatedEntries_idx__ > 0) {
        src = (uint8_t *)m_AffiliatedEntries_vector[m_AffiliatedEntries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_AffiliatedEntries_idx__++;
    if (!m_parse__) { (*m_Num_Affiliated)++; }
    size_t len = ptr->getLen();
    m_AffiliatedEntries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvMLDStructure::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_MLDMACAddr->struct_swap();
    for (size_t i = 0; i < m_AffiliatedEntries_idx__; i++){
        std::get<1>(AffiliatedEntries(i)).class_swap();
    }
}

bool tlvMLDStructure::finalize()
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

size_t tlvMLDStructure::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // MLDMACAddr
    class_size += 25 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint8_t); // Num_Affiliated
    return class_size;
}

bool tlvMLDStructure::init()
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
    m_MLDMACAddr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_MLDMACAddr->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (25))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (25) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 25;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 25); }
    }
    m_Num_Affiliated = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_Num_Affiliated = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_AffiliatedEntries = reinterpret_cast<cAffiliatedEntry*>(m_buff_ptr__);
    uint8_t Num_Affiliated = *m_Num_Affiliated;
    m_AffiliatedEntries_idx__ = 0;
    for (size_t i = 0; i < Num_Affiliated; i++) {
        auto AffiliatedEntries = create_AffiliatedEntries();
        if (!AffiliatedEntries || !AffiliatedEntries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_AffiliatedEntries() failed";
            return false;
        }
        if (!add_AffiliatedEntries(AffiliatedEntries)) {
            TLVF_LOG(ERROR) << "add_AffiliatedEntries() failed";
            return false;
        }
        // swap back since AffiliatedEntries will be swapped as part of the whole class swap
        AffiliatedEntries->class_swap();
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

cAffiliatedEntry::cAffiliatedEntry(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAffiliatedEntry::cAffiliatedEntry(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAffiliatedEntry::~cAffiliatedEntry() {
}
sMacAddr& cAffiliatedEntry::radio_bssid() {
    return (sMacAddr&)(*m_radio_bssid);
}

uint8_t* cAffiliatedEntry::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cAffiliatedEntry::set_reserved(const void* buffer, size_t size) {
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
void cAffiliatedEntry::class_swap()
{
    m_radio_bssid->struct_swap();
}

bool cAffiliatedEntry::finalize()
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

size_t cAffiliatedEntry::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // radio_bssid
    class_size += 25 * sizeof(uint8_t); // reserved
    return class_size;
}

bool cAffiliatedEntry::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_radio_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_radio_bssid->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (25))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (25) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 25;
    if (m_parse__) { class_swap(); }
    return true;
}


