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

#include <tlvf/wfa_map/tlvWiFi7AgentCapabilities.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvWiFi7AgentCapabilities::tlvWiFi7AgentCapabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvWiFi7AgentCapabilities::tlvWiFi7AgentCapabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvWiFi7AgentCapabilities::~tlvWiFi7AgentCapabilities() {
}
const eTlvTypeMap& tlvWiFi7AgentCapabilities::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvWiFi7AgentCapabilities::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvWiFi7AgentCapabilities::maxnumMLDs() {
    return (uint8_t&)(*m_maxnumMLDs);
}

tlvWiFi7AgentCapabilities::sFlags2& tlvWiFi7AgentCapabilities::flags() {
    return (sFlags2&)(*m_flags);
}

uint8_t* tlvWiFi7AgentCapabilities::reserved_2(size_t idx) {
    if ( (m_reserved_2_idx__ == 0) || (m_reserved_2_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_2[idx]);
}

bool tlvWiFi7AgentCapabilities::set_reserved_2(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_2 received a null pointer.";
        return false;
    }
    if (size > 13) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_2);
    return true;
}
uint8_t& tlvWiFi7AgentCapabilities::num_radio() {
    return (uint8_t&)(*m_num_radio);
}

std::tuple<bool, cRadioEntry&> tlvWiFi7AgentCapabilities::radioEntries(size_t idx) {
    bool ret_success = ( (m_radioEntries_idx__ > 0) && (m_radioEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_radioEntries_vector[ret_idx]));
}

std::shared_ptr<cRadioEntry> tlvWiFi7AgentCapabilities::create_radioEntries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list radioEntries, abort!";
        return nullptr;
    }
    size_t len = cRadioEntry::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_radioEntries;
    if (m_radioEntries_idx__ > 0) {
        src = (uint8_t *)m_radioEntries_vector[m_radioEntries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cRadioEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvWiFi7AgentCapabilities::add_radioEntries(std::shared_ptr<cRadioEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_radioEntries was called before add_radioEntries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_radioEntries;
    if (m_radioEntries_idx__ > 0) {
        src = (uint8_t *)m_radioEntries_vector[m_radioEntries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_radioEntries_idx__++;
    if (!m_parse__) { (*m_num_radio)++; }
    size_t len = ptr->getLen();
    m_radioEntries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvWiFi7AgentCapabilities::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_flags->struct_swap();
    for (size_t i = 0; i < m_radioEntries_idx__; i++){
        std::get<1>(radioEntries(i)).class_swap();
    }
}

bool tlvWiFi7AgentCapabilities::finalize()
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

size_t tlvWiFi7AgentCapabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // maxnumMLDs
    class_size += sizeof(sFlags2); // flags
    class_size += 13 * sizeof(uint8_t); // reserved_2
    class_size += sizeof(uint8_t); // num_radio
    return class_size;
}

bool tlvWiFi7AgentCapabilities::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_WIFI_7_AGENT_CAPABILITIES;
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
    m_maxnumMLDs = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_maxnumMLDs = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_flags = reinterpret_cast<sFlags2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags2); }
    if (!m_parse__) { m_flags->struct_init(); }
    m_reserved_2 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (13))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (13) << ") Failed!";
        return false;
    }
    m_reserved_2_idx__  = 13;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 13); }
    }
    m_num_radio = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_radio = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_radioEntries = reinterpret_cast<cRadioEntry*>(m_buff_ptr__);
    uint8_t num_radio = *m_num_radio;
    m_radioEntries_idx__ = 0;
    for (size_t i = 0; i < num_radio; i++) {
        auto radioEntries = create_radioEntries();
        if (!radioEntries || !radioEntries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_radioEntries() failed";
            return false;
        }
        if (!add_radioEntries(radioEntries)) {
            TLVF_LOG(ERROR) << "add_radioEntries() failed";
            return false;
        }
        // swap back since radioEntries will be swapped as part of the whole class swap
        radioEntries->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_WIFI_7_AGENT_CAPABILITIES) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_WIFI_7_AGENT_CAPABILITIES) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cRadioEntry::cRadioEntry(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cRadioEntry::cRadioEntry(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cRadioEntry::~cRadioEntry() {
}
sMacAddr& cRadioEntry::ruid() {
    return (sMacAddr&)(*m_ruid);
}

uint8_t* cRadioEntry::reserved_3(size_t idx) {
    if ( (m_reserved_3_idx__ == 0) || (m_reserved_3_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_3[idx]);
}

bool cRadioEntry::set_reserved_3(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_3 received a null pointer.";
        return false;
    }
    if (size > 24) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_3);
    return true;
}
cRadioEntry::sFlags4& cRadioEntry::flags() {
    return (sFlags4&)(*m_flags);
}

uint8_t& cRadioEntry::num_AP_STR_Records() {
    return (uint8_t&)(*m_num_AP_STR_Records);
}

std::tuple<bool, cAP_STR_Records&> cRadioEntry::AP_STR_Records(size_t idx) {
    bool ret_success = ( (m_AP_STR_Records_idx__ > 0) && (m_AP_STR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_AP_STR_Records_vector[ret_idx]));
}

std::shared_ptr<cAP_STR_Records> cRadioEntry::create_AP_STR_Records() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list AP_STR_Records, abort!";
        return nullptr;
    }
    size_t len = cAP_STR_Records::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_AP_STR_Records;
    if (m_AP_STR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_STR_Records_vector[m_AP_STR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_AP_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_AP_NSTR_Records) + len);
    m_AP_NSTR_Records = (cAP_NSTR_Records *)((uint8_t *)(m_AP_NSTR_Records) + len);
    m_num_AP_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLSR_Records) + len);
    m_AP_EMLSR_Records = (cAP_EMLSR_Records *)((uint8_t *)(m_AP_EMLSR_Records) + len);
    m_num_AP_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLMR_Records) + len);
    m_AP_EMLMR_Records = (cAP_EMLMR_Records *)((uint8_t *)(m_AP_EMLMR_Records) + len);
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len);
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len);
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len);
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len);
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len);
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len);
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cAP_STR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_AP_STR_Records(std::shared_ptr<cAP_STR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_AP_STR_Records was called before add_AP_STR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_AP_STR_Records;
    if (m_AP_STR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_STR_Records_vector[m_AP_STR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_AP_STR_Records_idx__++;
    if (!m_parse__) { (*m_num_AP_STR_Records)++; }
    size_t len = ptr->getLen();
    m_num_AP_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_AP_NSTR_Records) + len - ptr->get_initial_size());
    m_AP_NSTR_Records = (cAP_NSTR_Records *)((uint8_t *)(m_AP_NSTR_Records) + len - ptr->get_initial_size());
    m_num_AP_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLSR_Records) + len - ptr->get_initial_size());
    m_AP_EMLSR_Records = (cAP_EMLSR_Records *)((uint8_t *)(m_AP_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_AP_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_EMLMR_Records = (cAP_EMLMR_Records *)((uint8_t *)(m_AP_EMLMR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_STR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_AP_NSTR_Records() {
    return (uint8_t&)(*m_num_AP_NSTR_Records);
}

std::tuple<bool, cAP_NSTR_Records&> cRadioEntry::AP_NSTR_Records(size_t idx) {
    bool ret_success = ( (m_AP_NSTR_Records_idx__ > 0) && (m_AP_NSTR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_AP_NSTR_Records_vector[ret_idx]));
}

std::shared_ptr<cAP_NSTR_Records> cRadioEntry::create_AP_NSTR_Records() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list AP_NSTR_Records, abort!";
        return nullptr;
    }
    size_t len = cAP_NSTR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 1;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_AP_NSTR_Records;
    if (m_AP_NSTR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_NSTR_Records_vector[m_AP_NSTR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_AP_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLSR_Records) + len);
    m_AP_EMLSR_Records = (cAP_EMLSR_Records *)((uint8_t *)(m_AP_EMLSR_Records) + len);
    m_num_AP_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLMR_Records) + len);
    m_AP_EMLMR_Records = (cAP_EMLMR_Records *)((uint8_t *)(m_AP_EMLMR_Records) + len);
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len);
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len);
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len);
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len);
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len);
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len);
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cAP_NSTR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_AP_NSTR_Records(std::shared_ptr<cAP_NSTR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_AP_NSTR_Records was called before add_AP_NSTR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_AP_NSTR_Records;
    if (m_AP_NSTR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_NSTR_Records_vector[m_AP_NSTR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_AP_NSTR_Records_idx__++;
    if (!m_parse__) { (*m_num_AP_NSTR_Records)++; }
    size_t len = ptr->getLen();
    m_num_AP_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLSR_Records) + len - ptr->get_initial_size());
    m_AP_EMLSR_Records = (cAP_EMLSR_Records *)((uint8_t *)(m_AP_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_AP_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_EMLMR_Records = (cAP_EMLMR_Records *)((uint8_t *)(m_AP_EMLMR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_NSTR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_AP_EMLSR_Records() {
    return (uint8_t&)(*m_num_AP_EMLSR_Records);
}

std::tuple<bool, cAP_EMLSR_Records&> cRadioEntry::AP_EMLSR_Records(size_t idx) {
    bool ret_success = ( (m_AP_EMLSR_Records_idx__ > 0) && (m_AP_EMLSR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_AP_EMLSR_Records_vector[ret_idx]));
}

std::shared_ptr<cAP_EMLSR_Records> cRadioEntry::create_AP_EMLSR_Records() {
    if (m_lock_order_counter__ > 2) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list AP_EMLSR_Records, abort!";
        return nullptr;
    }
    size_t len = cAP_EMLSR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 2;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_AP_EMLSR_Records;
    if (m_AP_EMLSR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_EMLSR_Records_vector[m_AP_EMLSR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_AP_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLMR_Records) + len);
    m_AP_EMLMR_Records = (cAP_EMLMR_Records *)((uint8_t *)(m_AP_EMLMR_Records) + len);
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len);
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len);
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len);
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len);
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len);
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len);
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cAP_EMLSR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_AP_EMLSR_Records(std::shared_ptr<cAP_EMLSR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_AP_EMLSR_Records was called before add_AP_EMLSR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_AP_EMLSR_Records;
    if (m_AP_EMLSR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_EMLSR_Records_vector[m_AP_EMLSR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_AP_EMLSR_Records_idx__++;
    if (!m_parse__) { (*m_num_AP_EMLSR_Records)++; }
    size_t len = ptr->getLen();
    m_num_AP_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_AP_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_EMLMR_Records = (cAP_EMLMR_Records *)((uint8_t *)(m_AP_EMLMR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_EMLSR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_AP_EMLMR_Records() {
    return (uint8_t&)(*m_num_AP_EMLMR_Records);
}

std::tuple<bool, cAP_EMLMR_Records&> cRadioEntry::AP_EMLMR_Records(size_t idx) {
    bool ret_success = ( (m_AP_EMLMR_Records_idx__ > 0) && (m_AP_EMLMR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_AP_EMLMR_Records_vector[ret_idx]));
}

std::shared_ptr<cAP_EMLMR_Records> cRadioEntry::create_AP_EMLMR_Records() {
    if (m_lock_order_counter__ > 3) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list AP_EMLMR_Records, abort!";
        return nullptr;
    }
    size_t len = cAP_EMLMR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 3;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_AP_EMLMR_Records;
    if (m_AP_EMLMR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_EMLMR_Records_vector[m_AP_EMLMR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len);
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len);
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len);
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len);
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len);
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len);
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cAP_EMLMR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_AP_EMLMR_Records(std::shared_ptr<cAP_EMLMR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_AP_EMLMR_Records was called before add_AP_EMLMR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_AP_EMLMR_Records;
    if (m_AP_EMLMR_Records_idx__ > 0) {
        src = (uint8_t *)m_AP_EMLMR_Records_vector[m_AP_EMLMR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_AP_EMLMR_Records_idx__++;
    if (!m_parse__) { (*m_num_AP_EMLMR_Records)++; }
    size_t len = ptr->getLen();
    m_num_bSTA_STR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_bSTA_STR_Records = (cBSTA_STR_Records *)((uint8_t *)(m_bSTA_STR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_AP_EMLMR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_bSTA_STR_Records() {
    return (uint8_t&)(*m_num_bSTA_STR_Records);
}

std::tuple<bool, cBSTA_STR_Records&> cRadioEntry::bSTA_STR_Records(size_t idx) {
    bool ret_success = ( (m_bSTA_STR_Records_idx__ > 0) && (m_bSTA_STR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_bSTA_STR_Records_vector[ret_idx]));
}

std::shared_ptr<cBSTA_STR_Records> cRadioEntry::create_bSTA_STR_Records() {
    if (m_lock_order_counter__ > 4) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bSTA_STR_Records, abort!";
        return nullptr;
    }
    size_t len = cBSTA_STR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 4;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_bSTA_STR_Records;
    if (m_bSTA_STR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_STR_Records_vector[m_bSTA_STR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len);
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len);
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len);
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len);
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cBSTA_STR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_bSTA_STR_Records(std::shared_ptr<cBSTA_STR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bSTA_STR_Records was called before add_bSTA_STR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bSTA_STR_Records;
    if (m_bSTA_STR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_STR_Records_vector[m_bSTA_STR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bSTA_STR_Records_idx__++;
    if (!m_parse__) { (*m_num_bSTA_STR_Records)++; }
    size_t len = ptr->getLen();
    m_num_bSTA_NSTR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_bSTA_NSTR_Records = (cBSTA_NSTR_Records *)((uint8_t *)(m_bSTA_NSTR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_STR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_bSTA_NSTR_Records() {
    return (uint8_t&)(*m_num_bSTA_NSTR_Records);
}

std::tuple<bool, cBSTA_NSTR_Records&> cRadioEntry::bSTA_NSTR_Records(size_t idx) {
    bool ret_success = ( (m_bSTA_NSTR_Records_idx__ > 0) && (m_bSTA_NSTR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_bSTA_NSTR_Records_vector[ret_idx]));
}

std::shared_ptr<cBSTA_NSTR_Records> cRadioEntry::create_bSTA_NSTR_Records() {
    if (m_lock_order_counter__ > 5) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bSTA_NSTR_Records, abort!";
        return nullptr;
    }
    size_t len = cBSTA_NSTR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 5;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_bSTA_NSTR_Records;
    if (m_bSTA_NSTR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_NSTR_Records_vector[m_bSTA_NSTR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len);
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len);
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cBSTA_NSTR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_bSTA_NSTR_Records(std::shared_ptr<cBSTA_NSTR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bSTA_NSTR_Records was called before add_bSTA_NSTR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bSTA_NSTR_Records;
    if (m_bSTA_NSTR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_NSTR_Records_vector[m_bSTA_NSTR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bSTA_NSTR_Records_idx__++;
    if (!m_parse__) { (*m_num_bSTA_NSTR_Records)++; }
    size_t len = ptr->getLen();
    m_num_bSTA_EMLSR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records = (cBSTA_EMLSR_Records *)((uint8_t *)(m_bSTA_EMLSR_Records) + len - ptr->get_initial_size());
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_NSTR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_bSTA_EMLSR_Records() {
    return (uint8_t&)(*m_num_bSTA_EMLSR_Records);
}

std::tuple<bool, cBSTA_EMLSR_Records&> cRadioEntry::bSTA_EMLSR_Records(size_t idx) {
    bool ret_success = ( (m_bSTA_EMLSR_Records_idx__ > 0) && (m_bSTA_EMLSR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_bSTA_EMLSR_Records_vector[ret_idx]));
}

std::shared_ptr<cBSTA_EMLSR_Records> cRadioEntry::create_bSTA_EMLSR_Records() {
    if (m_lock_order_counter__ > 6) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bSTA_EMLSR_Records, abort!";
        return nullptr;
    }
    size_t len = cBSTA_EMLSR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 6;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_bSTA_EMLSR_Records;
    if (m_bSTA_EMLSR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_EMLSR_Records_vector[m_bSTA_EMLSR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len);
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len);
    return std::make_shared<cBSTA_EMLSR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_bSTA_EMLSR_Records(std::shared_ptr<cBSTA_EMLSR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bSTA_EMLSR_Records was called before add_bSTA_EMLSR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bSTA_EMLSR_Records;
    if (m_bSTA_EMLSR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_EMLSR_Records_vector[m_bSTA_EMLSR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bSTA_EMLSR_Records_idx__++;
    if (!m_parse__) { (*m_num_bSTA_EMLSR_Records)++; }
    size_t len = ptr->getLen();
    m_num_bSTA_EMLMR_Records = (uint8_t *)((uint8_t *)(m_num_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLMR_Records = (cBSTA_EMLMR_Records *)((uint8_t *)(m_bSTA_EMLMR_Records) + len - ptr->get_initial_size());
    m_bSTA_EMLSR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cRadioEntry::num_bSTA_EMLMR_Records() {
    return (uint8_t&)(*m_num_bSTA_EMLMR_Records);
}

std::tuple<bool, cBSTA_EMLMR_Records&> cRadioEntry::bSTA_EMLMR_Records(size_t idx) {
    bool ret_success = ( (m_bSTA_EMLMR_Records_idx__ > 0) && (m_bSTA_EMLMR_Records_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_bSTA_EMLMR_Records_vector[ret_idx]));
}

std::shared_ptr<cBSTA_EMLMR_Records> cRadioEntry::create_bSTA_EMLMR_Records() {
    if (m_lock_order_counter__ > 7) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bSTA_EMLMR_Records, abort!";
        return nullptr;
    }
    size_t len = cBSTA_EMLMR_Records::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 7;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_bSTA_EMLMR_Records;
    if (m_bSTA_EMLMR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_EMLMR_Records_vector[m_bSTA_EMLMR_Records_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cBSTA_EMLMR_Records>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_bSTA_EMLMR_Records(std::shared_ptr<cBSTA_EMLMR_Records> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bSTA_EMLMR_Records was called before add_bSTA_EMLMR_Records";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bSTA_EMLMR_Records;
    if (m_bSTA_EMLMR_Records_idx__ > 0) {
        src = (uint8_t *)m_bSTA_EMLMR_Records_vector[m_bSTA_EMLMR_Records_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bSTA_EMLMR_Records_idx__++;
    if (!m_parse__) { (*m_num_bSTA_EMLMR_Records)++; }
    size_t len = ptr->getLen();
    m_bSTA_EMLMR_Records_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cRadioEntry::class_swap()
{
    m_ruid->struct_swap();
    m_flags->struct_swap();
    for (size_t i = 0; i < m_AP_STR_Records_idx__; i++){
        std::get<1>(AP_STR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_AP_NSTR_Records_idx__; i++){
        std::get<1>(AP_NSTR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_AP_EMLSR_Records_idx__; i++){
        std::get<1>(AP_EMLSR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_AP_EMLMR_Records_idx__; i++){
        std::get<1>(AP_EMLMR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_bSTA_STR_Records_idx__; i++){
        std::get<1>(bSTA_STR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_bSTA_NSTR_Records_idx__; i++){
        std::get<1>(bSTA_NSTR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_bSTA_EMLSR_Records_idx__; i++){
        std::get<1>(bSTA_EMLSR_Records(i)).class_swap();
    }
    for (size_t i = 0; i < m_bSTA_EMLMR_Records_idx__; i++){
        std::get<1>(bSTA_EMLMR_Records(i)).class_swap();
    }
}

bool cRadioEntry::finalize()
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

size_t cRadioEntry::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // ruid
    class_size += 24 * sizeof(uint8_t); // reserved_3
    class_size += sizeof(sFlags4); // flags
    class_size += sizeof(uint8_t); // num_AP_STR_Records
    class_size += sizeof(uint8_t); // num_AP_NSTR_Records
    class_size += sizeof(uint8_t); // num_AP_EMLSR_Records
    class_size += sizeof(uint8_t); // num_AP_EMLMR_Records
    class_size += sizeof(uint8_t); // num_bSTA_STR_Records
    class_size += sizeof(uint8_t); // num_bSTA_NSTR_Records
    class_size += sizeof(uint8_t); // num_bSTA_EMLSR_Records
    class_size += sizeof(uint8_t); // num_bSTA_EMLMR_Records
    return class_size;
}

bool cRadioEntry::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_ruid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_ruid->struct_init(); }
    m_reserved_3 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (24))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (24) << ") Failed!";
        return false;
    }
    m_reserved_3_idx__  = 24;
    m_flags = reinterpret_cast<sFlags4*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags4))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags4) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    m_num_AP_STR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_AP_STR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_AP_STR_Records = reinterpret_cast<cAP_STR_Records*>(m_buff_ptr__);
    uint8_t num_AP_STR_Records = *m_num_AP_STR_Records;
    m_AP_STR_Records_idx__ = 0;
    for (size_t i = 0; i < num_AP_STR_Records; i++) {
        auto AP_STR_Records = create_AP_STR_Records();
        if (!AP_STR_Records || !AP_STR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_AP_STR_Records() failed";
            return false;
        }
        if (!add_AP_STR_Records(AP_STR_Records)) {
            TLVF_LOG(ERROR) << "add_AP_STR_Records() failed";
            return false;
        }
        // swap back since AP_STR_Records will be swapped as part of the whole class swap
        AP_STR_Records->class_swap();
    }
    m_num_AP_NSTR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_AP_NSTR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_AP_NSTR_Records = reinterpret_cast<cAP_NSTR_Records*>(m_buff_ptr__);
    uint8_t num_AP_NSTR_Records = *m_num_AP_NSTR_Records;
    m_AP_NSTR_Records_idx__ = 0;
    for (size_t i = 0; i < num_AP_NSTR_Records; i++) {
        auto AP_NSTR_Records = create_AP_NSTR_Records();
        if (!AP_NSTR_Records || !AP_NSTR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_AP_NSTR_Records() failed";
            return false;
        }
        if (!add_AP_NSTR_Records(AP_NSTR_Records)) {
            TLVF_LOG(ERROR) << "add_AP_NSTR_Records() failed";
            return false;
        }
        // swap back since AP_NSTR_Records will be swapped as part of the whole class swap
        AP_NSTR_Records->class_swap();
    }
    m_num_AP_EMLSR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_AP_EMLSR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_AP_EMLSR_Records = reinterpret_cast<cAP_EMLSR_Records*>(m_buff_ptr__);
    uint8_t num_AP_EMLSR_Records = *m_num_AP_EMLSR_Records;
    m_AP_EMLSR_Records_idx__ = 0;
    for (size_t i = 0; i < num_AP_EMLSR_Records; i++) {
        auto AP_EMLSR_Records = create_AP_EMLSR_Records();
        if (!AP_EMLSR_Records || !AP_EMLSR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_AP_EMLSR_Records() failed";
            return false;
        }
        if (!add_AP_EMLSR_Records(AP_EMLSR_Records)) {
            TLVF_LOG(ERROR) << "add_AP_EMLSR_Records() failed";
            return false;
        }
        // swap back since AP_EMLSR_Records will be swapped as part of the whole class swap
        AP_EMLSR_Records->class_swap();
    }
    m_num_AP_EMLMR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_AP_EMLMR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_AP_EMLMR_Records = reinterpret_cast<cAP_EMLMR_Records*>(m_buff_ptr__);
    uint8_t num_AP_EMLMR_Records = *m_num_AP_EMLMR_Records;
    m_AP_EMLMR_Records_idx__ = 0;
    for (size_t i = 0; i < num_AP_EMLMR_Records; i++) {
        auto AP_EMLMR_Records = create_AP_EMLMR_Records();
        if (!AP_EMLMR_Records || !AP_EMLMR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_AP_EMLMR_Records() failed";
            return false;
        }
        if (!add_AP_EMLMR_Records(AP_EMLMR_Records)) {
            TLVF_LOG(ERROR) << "add_AP_EMLMR_Records() failed";
            return false;
        }
        // swap back since AP_EMLMR_Records will be swapped as part of the whole class swap
        AP_EMLMR_Records->class_swap();
    }
    m_num_bSTA_STR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_bSTA_STR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bSTA_STR_Records = reinterpret_cast<cBSTA_STR_Records*>(m_buff_ptr__);
    uint8_t num_bSTA_STR_Records = *m_num_bSTA_STR_Records;
    m_bSTA_STR_Records_idx__ = 0;
    for (size_t i = 0; i < num_bSTA_STR_Records; i++) {
        auto bSTA_STR_Records = create_bSTA_STR_Records();
        if (!bSTA_STR_Records || !bSTA_STR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bSTA_STR_Records() failed";
            return false;
        }
        if (!add_bSTA_STR_Records(bSTA_STR_Records)) {
            TLVF_LOG(ERROR) << "add_bSTA_STR_Records() failed";
            return false;
        }
        // swap back since bSTA_STR_Records will be swapped as part of the whole class swap
        bSTA_STR_Records->class_swap();
    }
    m_num_bSTA_NSTR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_bSTA_NSTR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bSTA_NSTR_Records = reinterpret_cast<cBSTA_NSTR_Records*>(m_buff_ptr__);
    uint8_t num_bSTA_NSTR_Records = *m_num_bSTA_NSTR_Records;
    m_bSTA_NSTR_Records_idx__ = 0;
    for (size_t i = 0; i < num_bSTA_NSTR_Records; i++) {
        auto bSTA_NSTR_Records = create_bSTA_NSTR_Records();
        if (!bSTA_NSTR_Records || !bSTA_NSTR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bSTA_NSTR_Records() failed";
            return false;
        }
        if (!add_bSTA_NSTR_Records(bSTA_NSTR_Records)) {
            TLVF_LOG(ERROR) << "add_bSTA_NSTR_Records() failed";
            return false;
        }
        // swap back since bSTA_NSTR_Records will be swapped as part of the whole class swap
        bSTA_NSTR_Records->class_swap();
    }
    m_num_bSTA_EMLSR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_bSTA_EMLSR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bSTA_EMLSR_Records = reinterpret_cast<cBSTA_EMLSR_Records*>(m_buff_ptr__);
    uint8_t num_bSTA_EMLSR_Records = *m_num_bSTA_EMLSR_Records;
    m_bSTA_EMLSR_Records_idx__ = 0;
    for (size_t i = 0; i < num_bSTA_EMLSR_Records; i++) {
        auto bSTA_EMLSR_Records = create_bSTA_EMLSR_Records();
        if (!bSTA_EMLSR_Records || !bSTA_EMLSR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bSTA_EMLSR_Records() failed";
            return false;
        }
        if (!add_bSTA_EMLSR_Records(bSTA_EMLSR_Records)) {
            TLVF_LOG(ERROR) << "add_bSTA_EMLSR_Records() failed";
            return false;
        }
        // swap back since bSTA_EMLSR_Records will be swapped as part of the whole class swap
        bSTA_EMLSR_Records->class_swap();
    }
    m_num_bSTA_EMLMR_Records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_bSTA_EMLMR_Records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bSTA_EMLMR_Records = reinterpret_cast<cBSTA_EMLMR_Records*>(m_buff_ptr__);
    uint8_t num_bSTA_EMLMR_Records = *m_num_bSTA_EMLMR_Records;
    m_bSTA_EMLMR_Records_idx__ = 0;
    for (size_t i = 0; i < num_bSTA_EMLMR_Records; i++) {
        auto bSTA_EMLMR_Records = create_bSTA_EMLMR_Records();
        if (!bSTA_EMLMR_Records || !bSTA_EMLMR_Records->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bSTA_EMLMR_Records() failed";
            return false;
        }
        if (!add_bSTA_EMLMR_Records(bSTA_EMLMR_Records)) {
            TLVF_LOG(ERROR) << "add_bSTA_EMLMR_Records() failed";
            return false;
        }
        // swap back since bSTA_EMLMR_Records will be swapped as part of the whole class swap
        bSTA_EMLMR_Records->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cAP_STR_Records::cAP_STR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAP_STR_Records::cAP_STR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAP_STR_Records::~cAP_STR_Records() {
}
sMacAddr& cAP_STR_Records::AP_STR_RUID() {
    return (sMacAddr&)(*m_AP_STR_RUID);
}

cAP_STR_Records::sFlags5& cAP_STR_Records::flags() {
    return (sFlags5&)(*m_flags);
}

void cAP_STR_Records::class_swap()
{
    m_AP_STR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cAP_STR_Records::finalize()
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

size_t cAP_STR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // AP_STR_RUID
    class_size += sizeof(sFlags5); // flags
    return class_size;
}

bool cAP_STR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_AP_STR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_AP_STR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags5*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags5))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags5) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cAP_NSTR_Records::cAP_NSTR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAP_NSTR_Records::cAP_NSTR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAP_NSTR_Records::~cAP_NSTR_Records() {
}
sMacAddr& cAP_NSTR_Records::AP_NSTR_RUID() {
    return (sMacAddr&)(*m_AP_NSTR_RUID);
}

cAP_NSTR_Records::sFlags6& cAP_NSTR_Records::flags() {
    return (sFlags6&)(*m_flags);
}

void cAP_NSTR_Records::class_swap()
{
    m_AP_NSTR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cAP_NSTR_Records::finalize()
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

size_t cAP_NSTR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // AP_NSTR_RUID
    class_size += sizeof(sFlags6); // flags
    return class_size;
}

bool cAP_NSTR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_AP_NSTR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_AP_NSTR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags6*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags6))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags6) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cAP_EMLSR_Records::cAP_EMLSR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAP_EMLSR_Records::cAP_EMLSR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAP_EMLSR_Records::~cAP_EMLSR_Records() {
}
sMacAddr& cAP_EMLSR_Records::AP_EMLSR_RUID() {
    return (sMacAddr&)(*m_AP_EMLSR_RUID);
}

cAP_EMLSR_Records::sFlags7& cAP_EMLSR_Records::flags() {
    return (sFlags7&)(*m_flags);
}

void cAP_EMLSR_Records::class_swap()
{
    m_AP_EMLSR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cAP_EMLSR_Records::finalize()
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

size_t cAP_EMLSR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // AP_EMLSR_RUID
    class_size += sizeof(sFlags7); // flags
    return class_size;
}

bool cAP_EMLSR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_AP_EMLSR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_AP_EMLSR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags7*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags7))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags7) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cAP_EMLMR_Records::cAP_EMLMR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAP_EMLMR_Records::cAP_EMLMR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAP_EMLMR_Records::~cAP_EMLMR_Records() {
}
sMacAddr& cAP_EMLMR_Records::AP_EMLMR_RUID() {
    return (sMacAddr&)(*m_AP_EMLMR_RUID);
}

cAP_EMLMR_Records::sFlags8& cAP_EMLMR_Records::flags() {
    return (sFlags8&)(*m_flags);
}

void cAP_EMLMR_Records::class_swap()
{
    m_AP_EMLMR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cAP_EMLMR_Records::finalize()
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

size_t cAP_EMLMR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // AP_EMLMR_RUID
    class_size += sizeof(sFlags8); // flags
    return class_size;
}

bool cAP_EMLMR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_AP_EMLMR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_AP_EMLMR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags8*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags8))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags8) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cBSTA_STR_Records::cBSTA_STR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cBSTA_STR_Records::cBSTA_STR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cBSTA_STR_Records::~cBSTA_STR_Records() {
}
sMacAddr& cBSTA_STR_Records::bSTA_STR_RUID() {
    return (sMacAddr&)(*m_bSTA_STR_RUID);
}

cBSTA_STR_Records::sFlags9& cBSTA_STR_Records::flags() {
    return (sFlags9&)(*m_flags);
}

void cBSTA_STR_Records::class_swap()
{
    m_bSTA_STR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cBSTA_STR_Records::finalize()
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

size_t cBSTA_STR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bSTA_STR_RUID
    class_size += sizeof(sFlags9); // flags
    return class_size;
}

bool cBSTA_STR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bSTA_STR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bSTA_STR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags9*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags9))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags9) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cBSTA_NSTR_Records::cBSTA_NSTR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cBSTA_NSTR_Records::cBSTA_NSTR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cBSTA_NSTR_Records::~cBSTA_NSTR_Records() {
}
sMacAddr& cBSTA_NSTR_Records::bSTA_NSTR_RUID() {
    return (sMacAddr&)(*m_bSTA_NSTR_RUID);
}

cBSTA_NSTR_Records::sFlags10& cBSTA_NSTR_Records::flags() {
    return (sFlags10&)(*m_flags);
}

void cBSTA_NSTR_Records::class_swap()
{
    m_bSTA_NSTR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cBSTA_NSTR_Records::finalize()
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

size_t cBSTA_NSTR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bSTA_NSTR_RUID
    class_size += sizeof(sFlags10); // flags
    return class_size;
}

bool cBSTA_NSTR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bSTA_NSTR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bSTA_NSTR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags10*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags10))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags10) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cBSTA_EMLSR_Records::cBSTA_EMLSR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cBSTA_EMLSR_Records::cBSTA_EMLSR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cBSTA_EMLSR_Records::~cBSTA_EMLSR_Records() {
}
sMacAddr& cBSTA_EMLSR_Records::bSTA_EMLSR_RUID() {
    return (sMacAddr&)(*m_bSTA_EMLSR_RUID);
}

cBSTA_EMLSR_Records::sFlags11& cBSTA_EMLSR_Records::flags() {
    return (sFlags11&)(*m_flags);
}

void cBSTA_EMLSR_Records::class_swap()
{
    m_bSTA_EMLSR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cBSTA_EMLSR_Records::finalize()
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

size_t cBSTA_EMLSR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bSTA_EMLSR_RUID
    class_size += sizeof(sFlags11); // flags
    return class_size;
}

bool cBSTA_EMLSR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bSTA_EMLSR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bSTA_EMLSR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags11*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags11))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags11) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cBSTA_EMLMR_Records::cBSTA_EMLMR_Records(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cBSTA_EMLMR_Records::cBSTA_EMLMR_Records(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cBSTA_EMLMR_Records::~cBSTA_EMLMR_Records() {
}
sMacAddr& cBSTA_EMLMR_Records::bSTA_EMLMR_RUID() {
    return (sMacAddr&)(*m_bSTA_EMLMR_RUID);
}

cBSTA_EMLMR_Records::sFlags12& cBSTA_EMLMR_Records::flags() {
    return (sFlags12&)(*m_flags);
}

void cBSTA_EMLMR_Records::class_swap()
{
    m_bSTA_EMLMR_RUID->struct_swap();
    m_flags->struct_swap();
}

bool cBSTA_EMLMR_Records::finalize()
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

size_t cBSTA_EMLMR_Records::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bSTA_EMLMR_RUID
    class_size += sizeof(sFlags12); // flags
    return class_size;
}

bool cBSTA_EMLMR_Records::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bSTA_EMLMR_RUID = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bSTA_EMLMR_RUID->struct_init(); }
    m_flags = reinterpret_cast<sFlags12*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags12))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags12) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}


