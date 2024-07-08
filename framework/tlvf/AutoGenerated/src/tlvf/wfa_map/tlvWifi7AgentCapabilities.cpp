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

#include <tlvf/wfa_map/tlvWifi7AgentCapabilities.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvWifi7AgentCapabilities::tlvWifi7AgentCapabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvWifi7AgentCapabilities::tlvWifi7AgentCapabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvWifi7AgentCapabilities::~tlvWifi7AgentCapabilities() {
}
const eTlvTypeMap& tlvWifi7AgentCapabilities::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvWifi7AgentCapabilities::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvWifi7AgentCapabilities::max_num_mlds() {
    return (uint8_t&)(*m_max_num_mlds);
}

tlvWifi7AgentCapabilities::sFlags1& tlvWifi7AgentCapabilities::flags1() {
    return (sFlags1&)(*m_flags1);
}

tlvWifi7AgentCapabilities::sFlags2& tlvWifi7AgentCapabilities::flags2() {
    return (sFlags2&)(*m_flags2);
}

uint8_t* tlvWifi7AgentCapabilities::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvWifi7AgentCapabilities::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 13) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
uint8_t& tlvWifi7AgentCapabilities::num_radio() {
    return (uint8_t&)(*m_num_radio);
}

std::tuple<bool, cRadioWifi7Capabilities&> tlvWifi7AgentCapabilities::radio_wifi7_capabilities(size_t idx) {
    bool ret_success = ( (m_radio_wifi7_capabilities_idx__ > 0) && (m_radio_wifi7_capabilities_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_radio_wifi7_capabilities_vector[ret_idx]));
}

std::shared_ptr<cRadioWifi7Capabilities> tlvWifi7AgentCapabilities::create_radio_wifi7_capabilities() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list radio_wifi7_capabilities, abort!";
        return nullptr;
    }
    size_t len = cRadioWifi7Capabilities::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_radio_wifi7_capabilities;
    if (m_radio_wifi7_capabilities_idx__ > 0) {
        src = (uint8_t *)m_radio_wifi7_capabilities_vector[m_radio_wifi7_capabilities_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cRadioWifi7Capabilities>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvWifi7AgentCapabilities::add_radio_wifi7_capabilities(std::shared_ptr<cRadioWifi7Capabilities> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_radio_wifi7_capabilities was called before add_radio_wifi7_capabilities";
        return false;
    }
    uint8_t *src = (uint8_t *)m_radio_wifi7_capabilities;
    if (m_radio_wifi7_capabilities_idx__ > 0) {
        src = (uint8_t *)m_radio_wifi7_capabilities_vector[m_radio_wifi7_capabilities_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_radio_wifi7_capabilities_idx__++;
    if (!m_parse__) { (*m_num_radio)++; }
    size_t len = ptr->getLen();
    m_radio_wifi7_capabilities_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvWifi7AgentCapabilities::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_flags1->struct_swap();
    m_flags2->struct_swap();
    for (size_t i = 0; i < m_radio_wifi7_capabilities_idx__; i++){
        std::get<1>(radio_wifi7_capabilities(i)).class_swap();
    }
}

bool tlvWifi7AgentCapabilities::finalize()
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

size_t tlvWifi7AgentCapabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // max_num_mlds
    class_size += sizeof(sFlags1); // flags1
    class_size += sizeof(sFlags2); // flags2
    class_size += 13 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint8_t); // num_radio
    return class_size;
}

bool tlvWifi7AgentCapabilities::init()
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
    m_max_num_mlds = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_flags1 = reinterpret_cast<sFlags1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags1) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags1); }
    if (!m_parse__) { m_flags1->struct_init(); }
    m_flags2 = reinterpret_cast<sFlags2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags2); }
    if (!m_parse__) { m_flags2->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (13))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (13) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 13;
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
    m_radio_wifi7_capabilities = reinterpret_cast<cRadioWifi7Capabilities*>(m_buff_ptr__);
    uint8_t num_radio = *m_num_radio;
    m_radio_wifi7_capabilities_idx__ = 0;
    for (size_t i = 0; i < num_radio; i++) {
        auto radio_wifi7_capabilities = create_radio_wifi7_capabilities();
        if (!radio_wifi7_capabilities || !radio_wifi7_capabilities->isInitialized()) {
            TLVF_LOG(ERROR) << "create_radio_wifi7_capabilities() failed";
            return false;
        }
        if (!add_radio_wifi7_capabilities(radio_wifi7_capabilities)) {
            TLVF_LOG(ERROR) << "add_radio_wifi7_capabilities() failed";
            return false;
        }
        // swap back since radio_wifi7_capabilities will be swapped as part of the whole class swap
        radio_wifi7_capabilities->class_swap();
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

cRadioWifi7Capabilities::cRadioWifi7Capabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cRadioWifi7Capabilities::cRadioWifi7Capabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cRadioWifi7Capabilities::~cRadioWifi7Capabilities() {
}
sMacAddr& cRadioWifi7Capabilities::ruid() {
    return (sMacAddr&)(*m_ruid);
}

uint8_t* cRadioWifi7Capabilities::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cRadioWifi7Capabilities::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 24) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
cRadioWifi7Capabilities::sWifi7CapabilitiesSupport& cRadioWifi7Capabilities::ap_modes_support() {
    return (sWifi7CapabilitiesSupport&)(*m_ap_modes_support);
}

cRadioWifi7Capabilities::sWifi7CapabilitiesSupport& cRadioWifi7Capabilities::bsta_modes_support() {
    return (sWifi7CapabilitiesSupport&)(*m_bsta_modes_support);
}

bool cRadioWifi7Capabilities::isPostInitSucceeded() {
    if (!m_ap_wifi7_capabilities_init) {
        TLVF_LOG(ERROR) << "ap_wifi7_capabilities is not initialized";
        return false;
    }
    if (!m_bsta_wifi7_capabilities_init) {
        TLVF_LOG(ERROR) << "bsta_wifi7_capabilities is not initialized";
        return false;
    }
    return true; 
}

std::shared_ptr<cWifi7Capabilities> cRadioWifi7Capabilities::create_ap_wifi7_capabilities() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ap_wifi7_capabilities, abort!";
        return nullptr;
    }
    size_t len = cWifi7Capabilities::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_ap_wifi7_capabilities;
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_bsta_wifi7_capabilities = (cWifi7Capabilities *)((uint8_t *)(m_bsta_wifi7_capabilities) + len);
    return std::make_shared<cWifi7Capabilities>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioWifi7Capabilities::add_ap_wifi7_capabilities(std::shared_ptr<cWifi7Capabilities> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_ap_wifi7_capabilities was called before add_ap_wifi7_capabilities";
        return false;
    }
    uint8_t *src = (uint8_t *)m_ap_wifi7_capabilities;
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_ap_wifi7_capabilities_init = true;
    size_t len = ptr->getLen();
    m_bsta_wifi7_capabilities = (cWifi7Capabilities *)((uint8_t *)(m_bsta_wifi7_capabilities) + len - ptr->get_initial_size());
    m_ap_wifi7_capabilities_ptr = ptr;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

std::shared_ptr<cWifi7Capabilities> cRadioWifi7Capabilities::create_bsta_wifi7_capabilities() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bsta_wifi7_capabilities, abort!";
        return nullptr;
    }
    size_t len = cWifi7Capabilities::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_bsta_wifi7_capabilities;
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cWifi7Capabilities>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioWifi7Capabilities::add_bsta_wifi7_capabilities(std::shared_ptr<cWifi7Capabilities> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bsta_wifi7_capabilities was called before add_bsta_wifi7_capabilities";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bsta_wifi7_capabilities;
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bsta_wifi7_capabilities_init = true;
    size_t len = ptr->getLen();
    m_bsta_wifi7_capabilities_ptr = ptr;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cRadioWifi7Capabilities::class_swap()
{
    m_ruid->struct_swap();
    m_ap_modes_support->struct_swap();
    m_bsta_modes_support->struct_swap();
    if (m_ap_wifi7_capabilities_ptr) { m_ap_wifi7_capabilities_ptr->class_swap(); }
    if (m_bsta_wifi7_capabilities_ptr) { m_bsta_wifi7_capabilities_ptr->class_swap(); }
}

bool cRadioWifi7Capabilities::finalize()
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

size_t cRadioWifi7Capabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // ruid
    class_size += 24 * sizeof(uint8_t); // reserved
    class_size += sizeof(sWifi7CapabilitiesSupport); // ap_modes_support
    class_size += sizeof(sWifi7CapabilitiesSupport); // bsta_modes_support
    return class_size;
}

bool cRadioWifi7Capabilities::init()
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
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (24))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (24) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 24;
    m_ap_modes_support = reinterpret_cast<sWifi7CapabilitiesSupport*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sWifi7CapabilitiesSupport))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sWifi7CapabilitiesSupport) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_ap_modes_support->struct_init(); }
    m_bsta_modes_support = reinterpret_cast<sWifi7CapabilitiesSupport*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sWifi7CapabilitiesSupport))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sWifi7CapabilitiesSupport) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bsta_modes_support->struct_init(); }
    m_ap_wifi7_capabilities = reinterpret_cast<cWifi7Capabilities*>(m_buff_ptr__);
    if (m_parse__) {
        auto ap_wifi7_capabilities = create_ap_wifi7_capabilities();
        if (!ap_wifi7_capabilities || !ap_wifi7_capabilities->isInitialized()) {
            TLVF_LOG(ERROR) << "create_ap_wifi7_capabilities() failed";
            return false;
        }
        if (!add_ap_wifi7_capabilities(ap_wifi7_capabilities)) {
            TLVF_LOG(ERROR) << "add_ap_wifi7_capabilities() failed";
            return false;
        }
        // swap back since ap_wifi7_capabilities will be swapped as part of the whole class swap
        ap_wifi7_capabilities->class_swap();
    }
    m_bsta_wifi7_capabilities = reinterpret_cast<cWifi7Capabilities*>(m_buff_ptr__);
    if (m_parse__) {
        auto bsta_wifi7_capabilities = create_bsta_wifi7_capabilities();
        if (!bsta_wifi7_capabilities || !bsta_wifi7_capabilities->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bsta_wifi7_capabilities() failed";
            return false;
        }
        if (!add_bsta_wifi7_capabilities(bsta_wifi7_capabilities)) {
            TLVF_LOG(ERROR) << "add_bsta_wifi7_capabilities() failed";
            return false;
        }
        // swap back since bsta_wifi7_capabilities will be swapped as part of the whole class swap
        bsta_wifi7_capabilities->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cWifi7Capabilities::cWifi7Capabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cWifi7Capabilities::cWifi7Capabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cWifi7Capabilities::~cWifi7Capabilities() {
}
uint8_t& cWifi7Capabilities::num_str_records() {
    return (uint8_t&)(*m_num_str_records);
}

std::tuple<bool, cRadioConfig&> cWifi7Capabilities::str_config(size_t idx) {
    bool ret_success = ( (m_str_config_idx__ > 0) && (m_str_config_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_str_config_vector[ret_idx]));
}

std::shared_ptr<cRadioConfig> cWifi7Capabilities::create_str_config() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list str_config, abort!";
        return nullptr;
    }
    size_t len = cRadioConfig::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_str_config;
    if (m_str_config_idx__ > 0) {
        src = (uint8_t *)m_str_config_vector[m_str_config_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_nstr_records = (uint8_t *)((uint8_t *)(m_num_nstr_records) + len);
    m_nstr_config = (cRadioConfig *)((uint8_t *)(m_nstr_config) + len);
    m_num_emlsr_records = (uint8_t *)((uint8_t *)(m_num_emlsr_records) + len);
    m_emlsr_config = (cRadioConfig *)((uint8_t *)(m_emlsr_config) + len);
    m_num_emlmr_records = (uint8_t *)((uint8_t *)(m_num_emlmr_records) + len);
    m_emlmr_config = (cRadioConfig *)((uint8_t *)(m_emlmr_config) + len);
    return std::make_shared<cRadioConfig>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cWifi7Capabilities::add_str_config(std::shared_ptr<cRadioConfig> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_str_config was called before add_str_config";
        return false;
    }
    uint8_t *src = (uint8_t *)m_str_config;
    if (m_str_config_idx__ > 0) {
        src = (uint8_t *)m_str_config_vector[m_str_config_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_str_config_idx__++;
    if (!m_parse__) { (*m_num_str_records)++; }
    size_t len = ptr->getLen();
    m_num_nstr_records = (uint8_t *)((uint8_t *)(m_num_nstr_records) + len - ptr->get_initial_size());
    m_nstr_config = (cRadioConfig *)((uint8_t *)(m_nstr_config) + len - ptr->get_initial_size());
    m_num_emlsr_records = (uint8_t *)((uint8_t *)(m_num_emlsr_records) + len - ptr->get_initial_size());
    m_emlsr_config = (cRadioConfig *)((uint8_t *)(m_emlsr_config) + len - ptr->get_initial_size());
    m_num_emlmr_records = (uint8_t *)((uint8_t *)(m_num_emlmr_records) + len - ptr->get_initial_size());
    m_emlmr_config = (cRadioConfig *)((uint8_t *)(m_emlmr_config) + len - ptr->get_initial_size());
    m_str_config_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cWifi7Capabilities::num_nstr_records() {
    return (uint8_t&)(*m_num_nstr_records);
}

std::tuple<bool, cRadioConfig&> cWifi7Capabilities::nstr_config(size_t idx) {
    bool ret_success = ( (m_nstr_config_idx__ > 0) && (m_nstr_config_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_nstr_config_vector[ret_idx]));
}

std::shared_ptr<cRadioConfig> cWifi7Capabilities::create_nstr_config() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list nstr_config, abort!";
        return nullptr;
    }
    size_t len = cRadioConfig::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_nstr_config;
    if (m_nstr_config_idx__ > 0) {
        src = (uint8_t *)m_nstr_config_vector[m_nstr_config_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_emlsr_records = (uint8_t *)((uint8_t *)(m_num_emlsr_records) + len);
    m_emlsr_config = (cRadioConfig *)((uint8_t *)(m_emlsr_config) + len);
    m_num_emlmr_records = (uint8_t *)((uint8_t *)(m_num_emlmr_records) + len);
    m_emlmr_config = (cRadioConfig *)((uint8_t *)(m_emlmr_config) + len);
    return std::make_shared<cRadioConfig>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cWifi7Capabilities::add_nstr_config(std::shared_ptr<cRadioConfig> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_nstr_config was called before add_nstr_config";
        return false;
    }
    uint8_t *src = (uint8_t *)m_nstr_config;
    if (m_nstr_config_idx__ > 0) {
        src = (uint8_t *)m_nstr_config_vector[m_nstr_config_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_nstr_config_idx__++;
    if (!m_parse__) { (*m_num_nstr_records)++; }
    size_t len = ptr->getLen();
    m_num_emlsr_records = (uint8_t *)((uint8_t *)(m_num_emlsr_records) + len - ptr->get_initial_size());
    m_emlsr_config = (cRadioConfig *)((uint8_t *)(m_emlsr_config) + len - ptr->get_initial_size());
    m_num_emlmr_records = (uint8_t *)((uint8_t *)(m_num_emlmr_records) + len - ptr->get_initial_size());
    m_emlmr_config = (cRadioConfig *)((uint8_t *)(m_emlmr_config) + len - ptr->get_initial_size());
    m_nstr_config_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cWifi7Capabilities::num_emlsr_records() {
    return (uint8_t&)(*m_num_emlsr_records);
}

std::tuple<bool, cRadioConfig&> cWifi7Capabilities::emlsr_config(size_t idx) {
    bool ret_success = ( (m_emlsr_config_idx__ > 0) && (m_emlsr_config_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_emlsr_config_vector[ret_idx]));
}

std::shared_ptr<cRadioConfig> cWifi7Capabilities::create_emlsr_config() {
    if (m_lock_order_counter__ > 2) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list emlsr_config, abort!";
        return nullptr;
    }
    size_t len = cRadioConfig::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_emlsr_config;
    if (m_emlsr_config_idx__ > 0) {
        src = (uint8_t *)m_emlsr_config_vector[m_emlsr_config_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_emlmr_records = (uint8_t *)((uint8_t *)(m_num_emlmr_records) + len);
    m_emlmr_config = (cRadioConfig *)((uint8_t *)(m_emlmr_config) + len);
    return std::make_shared<cRadioConfig>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cWifi7Capabilities::add_emlsr_config(std::shared_ptr<cRadioConfig> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_emlsr_config was called before add_emlsr_config";
        return false;
    }
    uint8_t *src = (uint8_t *)m_emlsr_config;
    if (m_emlsr_config_idx__ > 0) {
        src = (uint8_t *)m_emlsr_config_vector[m_emlsr_config_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_emlsr_config_idx__++;
    if (!m_parse__) { (*m_num_emlsr_records)++; }
    size_t len = ptr->getLen();
    m_num_emlmr_records = (uint8_t *)((uint8_t *)(m_num_emlmr_records) + len - ptr->get_initial_size());
    m_emlmr_config = (cRadioConfig *)((uint8_t *)(m_emlmr_config) + len - ptr->get_initial_size());
    m_emlsr_config_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t& cWifi7Capabilities::num_emlmr_records() {
    return (uint8_t&)(*m_num_emlmr_records);
}

std::tuple<bool, cRadioConfig&> cWifi7Capabilities::emlmr_config(size_t idx) {
    bool ret_success = ( (m_emlmr_config_idx__ > 0) && (m_emlmr_config_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_emlmr_config_vector[ret_idx]));
}

std::shared_ptr<cRadioConfig> cWifi7Capabilities::create_emlmr_config() {
    if (m_lock_order_counter__ > 3) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list emlmr_config, abort!";
        return nullptr;
    }
    size_t len = cRadioConfig::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_emlmr_config;
    if (m_emlmr_config_idx__ > 0) {
        src = (uint8_t *)m_emlmr_config_vector[m_emlmr_config_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cRadioConfig>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cWifi7Capabilities::add_emlmr_config(std::shared_ptr<cRadioConfig> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_emlmr_config was called before add_emlmr_config";
        return false;
    }
    uint8_t *src = (uint8_t *)m_emlmr_config;
    if (m_emlmr_config_idx__ > 0) {
        src = (uint8_t *)m_emlmr_config_vector[m_emlmr_config_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_emlmr_config_idx__++;
    if (!m_parse__) { (*m_num_emlmr_records)++; }
    size_t len = ptr->getLen();
    m_emlmr_config_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cWifi7Capabilities::class_swap()
{
    for (size_t i = 0; i < m_str_config_idx__; i++){
        std::get<1>(str_config(i)).class_swap();
    }
    for (size_t i = 0; i < m_nstr_config_idx__; i++){
        std::get<1>(nstr_config(i)).class_swap();
    }
    for (size_t i = 0; i < m_emlsr_config_idx__; i++){
        std::get<1>(emlsr_config(i)).class_swap();
    }
    for (size_t i = 0; i < m_emlmr_config_idx__; i++){
        std::get<1>(emlmr_config(i)).class_swap();
    }
}

bool cWifi7Capabilities::finalize()
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

size_t cWifi7Capabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // num_str_records
    class_size += sizeof(uint8_t); // num_nstr_records
    class_size += sizeof(uint8_t); // num_emlsr_records
    class_size += sizeof(uint8_t); // num_emlmr_records
    return class_size;
}

bool cWifi7Capabilities::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_num_str_records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_str_records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_str_config = reinterpret_cast<cRadioConfig*>(m_buff_ptr__);
    uint8_t num_str_records = *m_num_str_records;
    m_str_config_idx__ = 0;
    for (size_t i = 0; i < num_str_records; i++) {
        auto str_config = create_str_config();
        if (!str_config || !str_config->isInitialized()) {
            TLVF_LOG(ERROR) << "create_str_config() failed";
            return false;
        }
        if (!add_str_config(str_config)) {
            TLVF_LOG(ERROR) << "add_str_config() failed";
            return false;
        }
        // swap back since str_config will be swapped as part of the whole class swap
        str_config->class_swap();
    }
    m_num_nstr_records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_nstr_records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_nstr_config = reinterpret_cast<cRadioConfig*>(m_buff_ptr__);
    uint8_t num_nstr_records = *m_num_nstr_records;
    m_nstr_config_idx__ = 0;
    for (size_t i = 0; i < num_nstr_records; i++) {
        auto nstr_config = create_nstr_config();
        if (!nstr_config || !nstr_config->isInitialized()) {
            TLVF_LOG(ERROR) << "create_nstr_config() failed";
            return false;
        }
        if (!add_nstr_config(nstr_config)) {
            TLVF_LOG(ERROR) << "add_nstr_config() failed";
            return false;
        }
        // swap back since nstr_config will be swapped as part of the whole class swap
        nstr_config->class_swap();
    }
    m_num_emlsr_records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_emlsr_records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_emlsr_config = reinterpret_cast<cRadioConfig*>(m_buff_ptr__);
    uint8_t num_emlsr_records = *m_num_emlsr_records;
    m_emlsr_config_idx__ = 0;
    for (size_t i = 0; i < num_emlsr_records; i++) {
        auto emlsr_config = create_emlsr_config();
        if (!emlsr_config || !emlsr_config->isInitialized()) {
            TLVF_LOG(ERROR) << "create_emlsr_config() failed";
            return false;
        }
        if (!add_emlsr_config(emlsr_config)) {
            TLVF_LOG(ERROR) << "add_emlsr_config() failed";
            return false;
        }
        // swap back since emlsr_config will be swapped as part of the whole class swap
        emlsr_config->class_swap();
    }
    m_num_emlmr_records = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_emlmr_records = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_emlmr_config = reinterpret_cast<cRadioConfig*>(m_buff_ptr__);
    uint8_t num_emlmr_records = *m_num_emlmr_records;
    m_emlmr_config_idx__ = 0;
    for (size_t i = 0; i < num_emlmr_records; i++) {
        auto emlmr_config = create_emlmr_config();
        if (!emlmr_config || !emlmr_config->isInitialized()) {
            TLVF_LOG(ERROR) << "create_emlmr_config() failed";
            return false;
        }
        if (!add_emlmr_config(emlmr_config)) {
            TLVF_LOG(ERROR) << "add_emlmr_config() failed";
            return false;
        }
        // swap back since emlmr_config will be swapped as part of the whole class swap
        emlmr_config->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cRadioConfig::cRadioConfig(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cRadioConfig::cRadioConfig(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cRadioConfig::~cRadioConfig() {
}
sMacAddr& cRadioConfig::ruid() {
    return (sMacAddr&)(*m_ruid);
}

cRadioConfig::sFrequencySeparation& cRadioConfig::frequency_separation() {
    return (sFrequencySeparation&)(*m_frequency_separation);
}

void cRadioConfig::class_swap()
{
    m_ruid->struct_swap();
    m_frequency_separation->struct_swap();
}

bool cRadioConfig::finalize()
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

size_t cRadioConfig::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sFrequencySeparation); // frequency_separation
    return class_size;
}

bool cRadioConfig::init()
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
    m_frequency_separation = reinterpret_cast<sFrequencySeparation*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFrequencySeparation))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFrequencySeparation) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_frequency_separation->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}


