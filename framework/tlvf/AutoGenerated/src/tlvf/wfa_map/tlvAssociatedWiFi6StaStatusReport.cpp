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

#include <tlvf/wfa_map/tlvAssociatedWiFi6StaStatusReport.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvAssociatedWiFi6StaStatusReport::tlvAssociatedWiFi6StaStatusReport(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvAssociatedWiFi6StaStatusReport::tlvAssociatedWiFi6StaStatusReport(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvAssociatedWiFi6StaStatusReport::~tlvAssociatedWiFi6StaStatusReport() {
}
const eTlvTypeMap& tlvAssociatedWiFi6StaStatusReport::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvAssociatedWiFi6StaStatusReport::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvAssociatedWiFi6StaStatusReport::sta_mac() {
    return (sMacAddr&)(*m_sta_mac);
}

uint8_t& tlvAssociatedWiFi6StaStatusReport::tid_queue_size_list_length() {
    return (uint8_t&)(*m_tid_queue_size_list_length);
}

std::tuple<bool, cTidQueueSize&> tlvAssociatedWiFi6StaStatusReport::tid_queue_size_list(size_t idx) {
    bool ret_success = ( (m_tid_queue_size_list_idx__ > 0) && (m_tid_queue_size_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_tid_queue_size_list_vector[ret_idx]));
}

std::shared_ptr<cTidQueueSize> tlvAssociatedWiFi6StaStatusReport::create_tid_queue_size_list() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list tid_queue_size_list, abort!";
        return nullptr;
    }
    size_t len = cTidQueueSize::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_tid_queue_size_list;
    if (m_tid_queue_size_list_idx__ > 0) {
        src = (uint8_t *)m_tid_queue_size_list_vector[m_tid_queue_size_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cTidQueueSize>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvAssociatedWiFi6StaStatusReport::add_tid_queue_size_list(std::shared_ptr<cTidQueueSize> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_tid_queue_size_list was called before add_tid_queue_size_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_tid_queue_size_list;
    if (m_tid_queue_size_list_idx__ > 0) {
        src = (uint8_t *)m_tid_queue_size_list_vector[m_tid_queue_size_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_tid_queue_size_list_idx__++;
    if (!m_parse__) { (*m_tid_queue_size_list_length)++; }
    size_t len = ptr->getLen();
    m_tid_queue_size_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvAssociatedWiFi6StaStatusReport::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_sta_mac->struct_swap();
    for (size_t i = 0; i < m_tid_queue_size_list_idx__; i++){
        std::get<1>(tid_queue_size_list(i)).class_swap();
    }
}

bool tlvAssociatedWiFi6StaStatusReport::finalize()
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

size_t tlvAssociatedWiFi6StaStatusReport::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // sta_mac
    class_size += sizeof(uint8_t); // tid_queue_size_list_length
    return class_size;
}

bool tlvAssociatedWiFi6StaStatusReport::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_ASSOCIATED_WIFI_6_STA_STATUS_REPORT;
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
    m_sta_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_sta_mac->struct_init(); }
    m_tid_queue_size_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_tid_queue_size_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_tid_queue_size_list = reinterpret_cast<cTidQueueSize*>(m_buff_ptr__);
    uint8_t tid_queue_size_list_length = *m_tid_queue_size_list_length;
    m_tid_queue_size_list_idx__ = 0;
    for (size_t i = 0; i < tid_queue_size_list_length; i++) {
        auto tid_queue_size_list = create_tid_queue_size_list();
        if (!tid_queue_size_list) {
            TLVF_LOG(ERROR) << "create_tid_queue_size_list() failed";
            return false;
        }
        if (!add_tid_queue_size_list(tid_queue_size_list)) {
            TLVF_LOG(ERROR) << "add_tid_queue_size_list() failed";
            return false;
        }
        // swap back since tid_queue_size_list will be swapped as part of the whole class swap
        tid_queue_size_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_ASSOCIATED_WIFI_6_STA_STATUS_REPORT) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_ASSOCIATED_WIFI_6_STA_STATUS_REPORT) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cTidQueueSize::cTidQueueSize(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cTidQueueSize::cTidQueueSize(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cTidQueueSize::~cTidQueueSize() {
}
uint8_t& cTidQueueSize::tid() {
    return (uint8_t&)(*m_tid);
}

uint8_t& cTidQueueSize::queue_size() {
    return (uint8_t&)(*m_queue_size);
}

void cTidQueueSize::class_swap()
{
}

bool cTidQueueSize::finalize()
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

size_t cTidQueueSize::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // tid
    class_size += sizeof(uint8_t); // queue_size
    return class_size;
}

bool cTidQueueSize::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_tid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_queue_size = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


