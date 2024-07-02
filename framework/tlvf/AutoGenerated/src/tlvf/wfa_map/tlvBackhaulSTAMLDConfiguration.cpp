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

#include <tlvf/wfa_map/tlvBackhaulSTAMLDConfiguration.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvBackhaulSTAMLDConfiguration::tlvBackhaulSTAMLDConfiguration(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvBackhaulSTAMLDConfiguration::tlvBackhaulSTAMLDConfiguration(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvBackhaulSTAMLDConfiguration::~tlvBackhaulSTAMLDConfiguration() {
}
const eTlvTypeMap& tlvBackhaulSTAMLDConfiguration::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvBackhaulSTAMLDConfiguration::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::bSTA_MLD_MAC_Addr_Valid() {
    return (uint8_t&)(*m_bSTA_MLD_MAC_Addr_Valid);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::AP_MLD_MAC_Addr_Valid() {
    return (uint8_t&)(*m_AP_MLD_MAC_Addr_Valid);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::reserved_1() {
    return (uint8_t&)(*m_reserved_1);
}

sMacAddr& tlvBackhaulSTAMLDConfiguration::bSTA_MLD_MAC_Addr() {
    return (sMacAddr&)(*m_bSTA_MLD_MAC_Addr);
}

sMacAddr& tlvBackhaulSTAMLDConfiguration::AP_MLD_MAC_Addr() {
    return (sMacAddr&)(*m_AP_MLD_MAC_Addr);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::STR() {
    return (uint8_t&)(*m_STR);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::NSTR() {
    return (uint8_t&)(*m_NSTR);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::EMLSR() {
    return (uint8_t&)(*m_EMLSR);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::EMLMR() {
    return (uint8_t&)(*m_EMLMR);
}

uint8_t& tlvBackhaulSTAMLDConfiguration::reserved_2() {
    return (uint8_t&)(*m_reserved_2);
}

uint8_t* tlvBackhaulSTAMLDConfiguration::reserved_3(size_t idx) {
    if ( (m_reserved_3_idx__ == 0) || (m_reserved_3_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_3[idx]);
}

bool tlvBackhaulSTAMLDConfiguration::set_reserved_3(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_3 received a null pointer.";
        return false;
    }
    if (size > 17) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_3);
    return true;
}
uint8_t& tlvBackhaulSTAMLDConfiguration::Num_AffiliatedAP() {
    return (uint8_t&)(*m_Num_AffiliatedAP);
}

std::tuple<bool, cAffiliatedAPEntry&> tlvBackhaulSTAMLDConfiguration::AffiliatedAPEntries(size_t idx) {
    bool ret_success = ( (m_AffiliatedAPEntries_idx__ > 0) && (m_AffiliatedAPEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_AffiliatedAPEntries_vector[ret_idx]));
}

std::shared_ptr<cAffiliatedAPEntry> tlvBackhaulSTAMLDConfiguration::create_AffiliatedAPEntries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list AffiliatedAPEntries, abort!";
        return nullptr;
    }
    size_t len = cAffiliatedAPEntry::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_AffiliatedAPEntries;
    if (m_AffiliatedAPEntries_idx__ > 0) {
        src = (uint8_t *)m_AffiliatedAPEntries_vector[m_AffiliatedAPEntries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cAffiliatedAPEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvBackhaulSTAMLDConfiguration::add_AffiliatedAPEntries(std::shared_ptr<cAffiliatedAPEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_AffiliatedAPEntries was called before add_AffiliatedAPEntries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_AffiliatedAPEntries;
    if (m_AffiliatedAPEntries_idx__ > 0) {
        src = (uint8_t *)m_AffiliatedAPEntries_vector[m_AffiliatedAPEntries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_AffiliatedAPEntries_idx__++;
    if (!m_parse__) { (*m_Num_AffiliatedAP)++; }
    size_t len = ptr->getLen();
    m_AffiliatedAPEntries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvBackhaulSTAMLDConfiguration::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_bSTA_MLD_MAC_Addr->struct_swap();
    m_AP_MLD_MAC_Addr->struct_swap();
    for (size_t i = 0; i < m_AffiliatedAPEntries_idx__; i++){
        std::get<1>(AffiliatedAPEntries(i)).class_swap();
    }
}

bool tlvBackhaulSTAMLDConfiguration::finalize()
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

size_t tlvBackhaulSTAMLDConfiguration::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // bSTA_MLD_MAC_Addr_Valid
    class_size += sizeof(uint8_t); // AP_MLD_MAC_Addr_Valid
    class_size += sizeof(uint8_t); // reserved_1
    class_size += sizeof(sMacAddr); // bSTA_MLD_MAC_Addr
    class_size += sizeof(sMacAddr); // AP_MLD_MAC_Addr
    class_size += sizeof(uint8_t); // STR
    class_size += sizeof(uint8_t); // NSTR
    class_size += sizeof(uint8_t); // EMLSR
    class_size += sizeof(uint8_t); // EMLMR
    class_size += sizeof(uint8_t); // reserved_2
    class_size += 17 * sizeof(uint8_t); // reserved_3
    class_size += sizeof(uint8_t); // Num_AffiliatedAP
    return class_size;
}

bool tlvBackhaulSTAMLDConfiguration::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_BACKHAUL_STA_MLD_CONFIGURATION;
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
    m_bSTA_MLD_MAC_Addr_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_AP_MLD_MAC_Addr_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_reserved_1 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_bSTA_MLD_MAC_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_bSTA_MLD_MAC_Addr->struct_init(); }
    m_AP_MLD_MAC_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_AP_MLD_MAC_Addr->struct_init(); }
    m_STR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_NSTR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_EMLSR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_EMLMR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_reserved_2 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_reserved_3 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (17))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (17) << ") Failed!";
        return false;
    }
    m_reserved_3_idx__  = 17;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 17); }
    }
    m_Num_AffiliatedAP = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_Num_AffiliatedAP = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_AffiliatedAPEntries = reinterpret_cast<cAffiliatedAPEntry*>(m_buff_ptr__);
    uint8_t Num_AffiliatedAP = *m_Num_AffiliatedAP;
    m_AffiliatedAPEntries_idx__ = 0;
    for (size_t i = 0; i < Num_AffiliatedAP; i++) {
        auto AffiliatedAPEntries = create_AffiliatedAPEntries();
        if (!AffiliatedAPEntries || !AffiliatedAPEntries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_AffiliatedAPEntries() failed";
            return false;
        }
        if (!add_AffiliatedAPEntries(AffiliatedAPEntries)) {
            TLVF_LOG(ERROR) << "add_AffiliatedAPEntries() failed";
            return false;
        }
        // swap back since AffiliatedAPEntries will be swapped as part of the whole class swap
        AffiliatedAPEntries->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_BACKHAUL_STA_MLD_CONFIGURATION) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_BACKHAUL_STA_MLD_CONFIGURATION) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cAffiliatedAPEntry::cAffiliatedAPEntry(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAffiliatedAPEntry::cAffiliatedAPEntry(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAffiliatedAPEntry::~cAffiliatedAPEntry() {
}
uint8_t& cAffiliatedAPEntry::Affiliated_AP_MAC_Addr_Valid() {
    return (uint8_t&)(*m_Affiliated_AP_MAC_Addr_Valid);
}

uint8_t& cAffiliatedAPEntry::reserved_4() {
    return (uint8_t&)(*m_reserved_4);
}

sMacAddr& cAffiliatedAPEntry::ruid() {
    return (sMacAddr&)(*m_ruid);
}

sMacAddr& cAffiliatedAPEntry::affiliated_AP_MAC_Addr() {
    return (sMacAddr&)(*m_affiliated_AP_MAC_Addr);
}

uint8_t* cAffiliatedAPEntry::reserved_5(size_t idx) {
    if ( (m_reserved_5_idx__ == 0) || (m_reserved_5_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_5[idx]);
}

bool cAffiliatedAPEntry::set_reserved_5(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_5 received a null pointer.";
        return false;
    }
    if (size > 19) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_5);
    return true;
}
void cAffiliatedAPEntry::class_swap()
{
    m_ruid->struct_swap();
    m_affiliated_AP_MAC_Addr->struct_swap();
}

bool cAffiliatedAPEntry::finalize()
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

size_t cAffiliatedAPEntry::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // Affiliated_AP_MAC_Addr_Valid
    class_size += sizeof(uint8_t); // reserved_4
    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sMacAddr); // affiliated_AP_MAC_Addr
    class_size += 19 * sizeof(uint8_t); // reserved_5
    return class_size;
}

bool cAffiliatedAPEntry::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_Affiliated_AP_MAC_Addr_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_4 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_ruid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_ruid->struct_init(); }
    m_affiliated_AP_MAC_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_affiliated_AP_MAC_Addr->struct_init(); }
    m_reserved_5 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (19))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (19) << ") Failed!";
        return false;
    }
    m_reserved_5_idx__  = 19;
    if (m_parse__) { class_swap(); }
    return true;
}


