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

#include <tlvf/wfa_map/tlvUnassociatedStaLinkMetricsQuery.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvUnassociatedStaLinkMetricsQuery::tlvUnassociatedStaLinkMetricsQuery(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvUnassociatedStaLinkMetricsQuery::tlvUnassociatedStaLinkMetricsQuery(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvUnassociatedStaLinkMetricsQuery::~tlvUnassociatedStaLinkMetricsQuery() {
}
const eTlvTypeMap& tlvUnassociatedStaLinkMetricsQuery::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvUnassociatedStaLinkMetricsQuery::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvUnassociatedStaLinkMetricsQuery::operating_class_of_channel_list() {
    return (uint8_t&)(*m_operating_class_of_channel_list);
}

uint8_t& tlvUnassociatedStaLinkMetricsQuery::channel_list_length() {
    return (uint8_t&)(*m_channel_list_length);
}

std::tuple<bool, cChannelParameters&> tlvUnassociatedStaLinkMetricsQuery::channel_list(size_t idx) {
    bool ret_success = ( (m_channel_list_idx__ > 0) && (m_channel_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_channel_list_vector[ret_idx]));
}

std::shared_ptr<cChannelParameters> tlvUnassociatedStaLinkMetricsQuery::create_channel_list() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list channel_list, abort!";
        return nullptr;
    }
    size_t len = cChannelParameters::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_channel_list;
    if (m_channel_list_idx__ > 0) {
        src = (uint8_t *)m_channel_list_vector[m_channel_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cChannelParameters>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvUnassociatedStaLinkMetricsQuery::add_channel_list(std::shared_ptr<cChannelParameters> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_channel_list was called before add_channel_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_channel_list;
    if (m_channel_list_idx__ > 0) {
        src = (uint8_t *)m_channel_list_vector[m_channel_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_channel_list_idx__++;
    if (!m_parse__) { (*m_channel_list_length)++; }
    size_t len = ptr->getLen();
    m_channel_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvUnassociatedStaLinkMetricsQuery::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_channel_list_idx__; i++){
        std::get<1>(channel_list(i)).class_swap();
    }
}

bool tlvUnassociatedStaLinkMetricsQuery::finalize()
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

size_t tlvUnassociatedStaLinkMetricsQuery::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // operating_class_of_channel_list
    class_size += sizeof(uint8_t); // channel_list_length
    return class_size;
}

bool tlvUnassociatedStaLinkMetricsQuery::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY;
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
    m_operating_class_of_channel_list = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_channel_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_channel_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_channel_list = reinterpret_cast<cChannelParameters*>(m_buff_ptr__);
    uint8_t channel_list_length = *m_channel_list_length;
    m_channel_list_idx__ = 0;
    for (size_t i = 0; i < channel_list_length; i++) {
        auto channel_list = create_channel_list();
        if (!channel_list || !channel_list->isInitialized()) {
            TLVF_LOG(ERROR) << "create_channel_list() failed";
            return false;
        }
        if (!add_channel_list(channel_list)) {
            TLVF_LOG(ERROR) << "add_channel_list() failed";
            return false;
        }
        // swap back since channel_list will be swapped as part of the whole class swap
        channel_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cChannelParameters::cChannelParameters(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cChannelParameters::cChannelParameters(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cChannelParameters::~cChannelParameters() {
}
uint8_t& cChannelParameters::channel_number() {
    return (uint8_t&)(*m_channel_number);
}

uint8_t& cChannelParameters::sta_list_length() {
    return (uint8_t&)(*m_sta_list_length);
}

std::tuple<bool, sMacAddr&> cChannelParameters::sta_list(size_t idx) {
    bool ret_success = ( (m_sta_list_idx__ > 0) && (m_sta_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_sta_list[ret_idx]);
}

bool cChannelParameters::alloc_sta_list(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list sta_list, abort!";
        return false;
    }
    size_t len = sizeof(sMacAddr) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_sta_list[*m_sta_list_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_sta_list_idx__ += count;
    *m_sta_list_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if (!m_parse__) { 
        for (size_t i = m_sta_list_idx__ - count; i < m_sta_list_idx__; i++) { m_sta_list[i].struct_init(); }
    }
    return true;
}

void cChannelParameters::class_swap()
{
    for (size_t i = 0; i < m_sta_list_idx__; i++){
        m_sta_list[i].struct_swap();
    }
}

bool cChannelParameters::finalize()
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

size_t cChannelParameters::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // channel_number
    class_size += sizeof(uint8_t); // sta_list_length
    return class_size;
}

bool cChannelParameters::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_channel_number = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_sta_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_sta_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_sta_list = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    uint8_t sta_list_length = *m_sta_list_length;
    m_sta_list_idx__ = sta_list_length;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr) * (sta_list_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) * (sta_list_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


