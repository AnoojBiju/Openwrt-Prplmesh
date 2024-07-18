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

#include <tlvf/wfa_map/tlvTidToLinkMappingPolicy.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvTidToLinkMappingPolicy::tlvTidToLinkMappingPolicy(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvTidToLinkMappingPolicy::tlvTidToLinkMappingPolicy(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvTidToLinkMappingPolicy::~tlvTidToLinkMappingPolicy() {
}
const eTlvTypeMap& tlvTidToLinkMappingPolicy::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvTidToLinkMappingPolicy::length() {
    return (const uint16_t&)(*m_length);
}

tlvTidToLinkMappingPolicy::sIsBStaConfig& tlvTidToLinkMappingPolicy::is_bsta_config() {
    return (sIsBStaConfig&)(*m_is_bsta_config);
}

sMacAddr& tlvTidToLinkMappingPolicy::mld_mac_addr() {
    return (sMacAddr&)(*m_mld_mac_addr);
}

tlvTidToLinkMappingPolicy::sTidToLinkMappingNegotiation& tlvTidToLinkMappingPolicy::tid_to_link_mapping_negotiation() {
    return (sTidToLinkMappingNegotiation&)(*m_tid_to_link_mapping_negotiation);
}

uint8_t* tlvTidToLinkMappingPolicy::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvTidToLinkMappingPolicy::set_reserved(const void* buffer, size_t size) {
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
uint16_t& tlvTidToLinkMappingPolicy::num_mapping() {
    return (uint16_t&)(*m_num_mapping);
}

std::tuple<bool, cMapping&> tlvTidToLinkMappingPolicy::mapping(size_t idx) {
    bool ret_success = ( (m_mapping_idx__ > 0) && (m_mapping_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_mapping_vector[ret_idx]));
}

std::shared_ptr<cMapping> tlvTidToLinkMappingPolicy::create_mapping() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list mapping, abort!";
        return nullptr;
    }
    size_t len = cMapping::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_mapping;
    if (m_mapping_idx__ > 0) {
        src = (uint8_t *)m_mapping_vector[m_mapping_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cMapping>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvTidToLinkMappingPolicy::add_mapping(std::shared_ptr<cMapping> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_mapping was called before add_mapping";
        return false;
    }
    uint8_t *src = (uint8_t *)m_mapping;
    if (m_mapping_idx__ > 0) {
        src = (uint8_t *)m_mapping_vector[m_mapping_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_mapping_idx__++;
    if (!m_parse__) { (*m_num_mapping)++; }
    size_t len = ptr->getLen();
    m_mapping_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvTidToLinkMappingPolicy::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_is_bsta_config->struct_swap();
    m_mld_mac_addr->struct_swap();
    m_tid_to_link_mapping_negotiation->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_num_mapping));
    for (size_t i = 0; i < m_mapping_idx__; i++){
        std::get<1>(mapping(i)).class_swap();
    }
}

bool tlvTidToLinkMappingPolicy::finalize()
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

size_t tlvTidToLinkMappingPolicy::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sIsBStaConfig); // is_bsta_config
    class_size += sizeof(sMacAddr); // mld_mac_addr
    class_size += sizeof(sTidToLinkMappingNegotiation); // tid_to_link_mapping_negotiation
    class_size += 22 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint16_t); // num_mapping
    return class_size;
}

bool tlvTidToLinkMappingPolicy::init()
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
    m_is_bsta_config = reinterpret_cast<sIsBStaConfig*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sIsBStaConfig))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sIsBStaConfig) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sIsBStaConfig); }
    if (!m_parse__) { m_is_bsta_config->struct_init(); }
    m_mld_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_mld_mac_addr->struct_init(); }
    m_tid_to_link_mapping_negotiation = reinterpret_cast<sTidToLinkMappingNegotiation*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sTidToLinkMappingNegotiation))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sTidToLinkMappingNegotiation) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sTidToLinkMappingNegotiation); }
    if (!m_parse__) { m_tid_to_link_mapping_negotiation->struct_init(); }
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
    if (!m_parse__) *m_num_mapping = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_mapping = reinterpret_cast<cMapping*>(m_buff_ptr__);
    uint16_t num_mapping = *m_num_mapping;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&num_mapping)); }
    m_mapping_idx__ = 0;
    for (size_t i = 0; i < num_mapping; i++) {
        auto mapping = create_mapping();
        if (!mapping || !mapping->isInitialized()) {
            TLVF_LOG(ERROR) << "create_mapping() failed";
            return false;
        }
        if (!add_mapping(mapping)) {
            TLVF_LOG(ERROR) << "add_mapping() failed";
            return false;
        }
        // swap back since mapping will be swapped as part of the whole class swap
        mapping->class_swap();
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

cMapping::cMapping(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cMapping::cMapping(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cMapping::~cMapping() {
}
cMapping::sAddRemove& cMapping::add_remove() {
    return (sAddRemove&)(*m_add_remove);
}

sMacAddr& cMapping::sta_mld_mac_addr() {
    return (sMacAddr&)(*m_sta_mld_mac_addr);
}

bool cMapping::isPostInitSucceeded() {
    if (!m_tid_to_link_control_field_init) {
        TLVF_LOG(ERROR) << "tid_to_link_control_field is not initialized";
        return false;
    }
    return true; 
}

std::shared_ptr<cTidToLinkControlField> cMapping::create_tid_to_link_control_field() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list tid_to_link_control_field, abort!";
        return nullptr;
    }
    size_t len = cTidToLinkControlField::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_tid_to_link_control_field;
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_tid_to_link_mapping = (sTidToLinkMapping *)((uint8_t *)(m_tid_to_link_mapping) + len);
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len);
    return std::make_shared<cTidToLinkControlField>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cMapping::add_tid_to_link_control_field(std::shared_ptr<cTidToLinkControlField> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_tid_to_link_control_field was called before add_tid_to_link_control_field";
        return false;
    }
    uint8_t *src = (uint8_t *)m_tid_to_link_control_field;
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_tid_to_link_control_field_init = true;
    size_t len = ptr->getLen();
    m_tid_to_link_mapping = (sTidToLinkMapping *)((uint8_t *)(m_tid_to_link_mapping) + len - ptr->get_initial_size());
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len - ptr->get_initial_size());
    m_tid_to_link_control_field_ptr = ptr;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

cMapping::sTidToLinkMapping& cMapping::tid_to_link_mapping() {
    return (sTidToLinkMapping&)(*m_tid_to_link_mapping);
}

uint8_t* cMapping::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cMapping::set_reserved(const void* buffer, size_t size) {
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
void cMapping::class_swap()
{
    m_add_remove->struct_swap();
    m_sta_mld_mac_addr->struct_swap();
    if (m_tid_to_link_control_field_ptr) { m_tid_to_link_control_field_ptr->class_swap(); }
    m_tid_to_link_mapping->struct_swap();
}

bool cMapping::finalize()
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

size_t cMapping::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sAddRemove); // add_remove
    class_size += sizeof(sMacAddr); // sta_mld_mac_addr
    class_size += sizeof(sTidToLinkMapping); // tid_to_link_mapping
    class_size += 7 * sizeof(uint8_t); // reserved
    return class_size;
}

bool cMapping::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_add_remove = reinterpret_cast<sAddRemove*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sAddRemove))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sAddRemove) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_add_remove->struct_init(); }
    m_sta_mld_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_sta_mld_mac_addr->struct_init(); }
    m_tid_to_link_control_field = reinterpret_cast<cTidToLinkControlField*>(m_buff_ptr__);
    if (m_parse__) {
        auto tid_to_link_control_field = create_tid_to_link_control_field();
        if (!tid_to_link_control_field || !tid_to_link_control_field->isInitialized()) {
            TLVF_LOG(ERROR) << "create_tid_to_link_control_field() failed";
            return false;
        }
        if (!add_tid_to_link_control_field(tid_to_link_control_field)) {
            TLVF_LOG(ERROR) << "add_tid_to_link_control_field() failed";
            return false;
        }
        // swap back since tid_to_link_control_field will be swapped as part of the whole class swap
        tid_to_link_control_field->class_swap();
    }
    m_tid_to_link_mapping = reinterpret_cast<sTidToLinkMapping*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sTidToLinkMapping))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sTidToLinkMapping) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_tid_to_link_mapping->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (7))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (7) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 7;
    if (m_parse__) { class_swap(); }
    return true;
}

cTidToLinkControlField::cTidToLinkControlField(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cTidToLinkControlField::cTidToLinkControlField(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cTidToLinkControlField::~cTidToLinkControlField() {
}
cTidToLinkControlField::sTidToLinkControl& cTidToLinkControlField::tid_to_link_control() {
    return (sTidToLinkControl&)(*m_tid_to_link_control);
}

uint8_t& cTidToLinkControlField::link_mapping_presence_indicator() {
    return (uint8_t&)(*m_link_mapping_presence_indicator);
}

uint8_t* cTidToLinkControlField::expected_duration(size_t idx) {
    if ( (m_expected_duration_idx__ == 0) || (m_expected_duration_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_expected_duration[idx]);
}

bool cTidToLinkControlField::set_expected_duration(const void* buffer, size_t size) {
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
void cTidToLinkControlField::class_swap()
{
    m_tid_to_link_control->struct_swap();
}

bool cTidToLinkControlField::finalize()
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

size_t cTidToLinkControlField::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sTidToLinkControl); // tid_to_link_control
    class_size += sizeof(uint8_t); // link_mapping_presence_indicator
    class_size += 3 * sizeof(uint8_t); // expected_duration
    return class_size;
}

bool cTidToLinkControlField::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_tid_to_link_control = reinterpret_cast<sTidToLinkControl*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sTidToLinkControl))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sTidToLinkControl) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_tid_to_link_control->struct_init(); }
    m_link_mapping_presence_indicator = reinterpret_cast<uint8_t*>(m_buff_ptr__);
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
    if (m_parse__) { class_swap(); }
    return true;
}


