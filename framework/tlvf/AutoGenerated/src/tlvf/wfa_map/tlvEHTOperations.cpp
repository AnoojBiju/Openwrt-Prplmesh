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

#include <tlvf/wfa_map/tlvEHTOperations.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvEHTOperations::tlvEHTOperations(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvEHTOperations::tlvEHTOperations(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvEHTOperations::~tlvEHTOperations() {
}
const eTlvTypeMap& tlvEHTOperations::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvEHTOperations::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t* tlvEHTOperations::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool tlvEHTOperations::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 32) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
uint8_t& tlvEHTOperations::num_radio() {
    return (uint8_t&)(*m_num_radio);
}

std::tuple<bool, cRadioEntry&> tlvEHTOperations::radio_entries(size_t idx) {
    bool ret_success = ( (m_radio_entries_idx__ > 0) && (m_radio_entries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_radio_entries_vector[ret_idx]));
}

std::shared_ptr<cRadioEntry> tlvEHTOperations::create_radio_entries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list radio_entries, abort!";
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
    uint8_t *src = (uint8_t *)m_radio_entries;
    if (m_radio_entries_idx__ > 0) {
        src = (uint8_t *)m_radio_entries_vector[m_radio_entries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cRadioEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvEHTOperations::add_radio_entries(std::shared_ptr<cRadioEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_radio_entries was called before add_radio_entries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_radio_entries;
    if (m_radio_entries_idx__ > 0) {
        src = (uint8_t *)m_radio_entries_vector[m_radio_entries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_radio_entries_idx__++;
    if (!m_parse__) { (*m_num_radio)++; }
    size_t len = ptr->getLen();
    m_radio_entries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvEHTOperations::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_radio_entries_idx__; i++){
        std::get<1>(radio_entries(i)).class_swap();
    }
}

bool tlvEHTOperations::finalize()
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

size_t tlvEHTOperations::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += 32 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint8_t); // num_radio
    return class_size;
}

bool tlvEHTOperations::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_EHT_OPERATIONS;
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
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (32))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (32) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 32;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 32); }
    }
    m_num_radio = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_radio = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_radio_entries = reinterpret_cast<cRadioEntry*>(m_buff_ptr__);
    uint8_t num_radio = *m_num_radio;
    m_radio_entries_idx__ = 0;
    for (size_t i = 0; i < num_radio; i++) {
        auto radio_entries = create_radio_entries();
        if (!radio_entries || !radio_entries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_radio_entries() failed";
            return false;
        }
        if (!add_radio_entries(radio_entries)) {
            TLVF_LOG(ERROR) << "add_radio_entries() failed";
            return false;
        }
        // swap back since radio_entries will be swapped as part of the whole class swap
        radio_entries->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_EHT_OPERATIONS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_EHT_OPERATIONS) << ", received value: " << int(*m_type);
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

uint8_t& cRadioEntry::num_bss() {
    return (uint8_t&)(*m_num_bss);
}

std::tuple<bool, cBssEntry&> cRadioEntry::bss_entries(size_t idx) {
    bool ret_success = ( (m_bss_entries_idx__ > 0) && (m_bss_entries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_bss_entries_vector[ret_idx]));
}

std::shared_ptr<cBssEntry> cRadioEntry::create_bss_entries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bss_entries, abort!";
        return nullptr;
    }
    size_t len = cBssEntry::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_bss_entries;
    if (m_bss_entries_idx__ > 0) {
        src = (uint8_t *)m_bss_entries_vector[m_bss_entries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len);
    return std::make_shared<cBssEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_bss_entries(std::shared_ptr<cBssEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bss_entries was called before add_bss_entries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bss_entries;
    if (m_bss_entries_idx__ > 0) {
        src = (uint8_t *)m_bss_entries_vector[m_bss_entries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bss_entries_idx__++;
    if (!m_parse__) { (*m_num_bss)++; }
    size_t len = ptr->getLen();
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len - ptr->get_initial_size());
    m_bss_entries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t* cRadioEntry::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cRadioEntry::set_reserved(const void* buffer, size_t size) {
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
void cRadioEntry::class_swap()
{
    m_ruid->struct_swap();
    for (size_t i = 0; i < m_bss_entries_idx__; i++){
        std::get<1>(bss_entries(i)).class_swap();
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
    class_size += sizeof(uint8_t); // num_bss
    class_size += 25 * sizeof(uint8_t); // reserved
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
    m_num_bss = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_bss = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bss_entries = reinterpret_cast<cBssEntry*>(m_buff_ptr__);
    uint8_t num_bss = *m_num_bss;
    m_bss_entries_idx__ = 0;
    for (size_t i = 0; i < num_bss; i++) {
        auto bss_entries = create_bss_entries();
        if (!bss_entries || !bss_entries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bss_entries() failed";
            return false;
        }
        if (!add_bss_entries(bss_entries)) {
            TLVF_LOG(ERROR) << "add_bss_entries() failed";
            return false;
        }
        // swap back since bss_entries will be swapped as part of the whole class swap
        bss_entries->class_swap();
    }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (25))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (25) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 25;
    if (m_parse__) { class_swap(); }
    return true;
}

cBssEntry::cBssEntry(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cBssEntry::cBssEntry(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cBssEntry::~cBssEntry() {
}
sMacAddr& cBssEntry::bssid() {
    return (sMacAddr&)(*m_bssid);
}

cBssEntry::sFlags& cBssEntry::flags() {
    return (sFlags&)(*m_flags);
}

uint8_t* cBssEntry::basic_eht_mcs_and_nss_set(size_t idx) {
    if ( (m_basic_eht_mcs_and_nss_set_idx__ == 0) || (m_basic_eht_mcs_and_nss_set_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_basic_eht_mcs_and_nss_set[idx]);
}

bool cBssEntry::set_basic_eht_mcs_and_nss_set(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_basic_eht_mcs_and_nss_set received a null pointer.";
        return false;
    }
    if (size > 32) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_basic_eht_mcs_and_nss_set);
    return true;
}
uint8_t& cBssEntry::control() {
    return (uint8_t&)(*m_control);
}

uint8_t& cBssEntry::ccfs0() {
    return (uint8_t&)(*m_ccfs0);
}

uint8_t& cBssEntry::ccfs1() {
    return (uint8_t&)(*m_ccfs1);
}

uint16_t& cBssEntry::disabled_subchannel_bitmap() {
    return (uint16_t&)(*m_disabled_subchannel_bitmap);
}

uint8_t* cBssEntry::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cBssEntry::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 16) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
void cBssEntry::class_swap()
{
    m_bssid->struct_swap();
    m_flags->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_disabled_subchannel_bitmap));
}

bool cBssEntry::finalize()
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

size_t cBssEntry::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(sFlags); // flags
    class_size += 32 * sizeof(uint8_t); // basic_eht_mcs_and_nss_set
    class_size += sizeof(uint8_t); // control
    class_size += sizeof(uint8_t); // ccfs0
    class_size += sizeof(uint8_t); // ccfs1
    class_size += sizeof(uint16_t); // disabled_subchannel_bitmap
    class_size += 16 * sizeof(uint8_t); // reserved
    return class_size;
}

bool cBssEntry::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_flags = reinterpret_cast<sFlags*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags->struct_init(); }
    m_basic_eht_mcs_and_nss_set = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (32))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (32) << ") Failed!";
        return false;
    }
    m_basic_eht_mcs_and_nss_set_idx__  = 32;
    m_control = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_ccfs0 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_ccfs1 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_disabled_subchannel_bitmap = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_disabled_subchannel_bitmap = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (16))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (16) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 16;
    if (m_parse__) { class_swap(); }
    return true;
}


