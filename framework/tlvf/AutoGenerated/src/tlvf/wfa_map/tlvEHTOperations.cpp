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

uint32_t& tlvEHTOperations::reserved() {
    return (uint32_t&)(*m_reserved);
}

uint8_t& tlvEHTOperations::num_radio() {
    return (uint8_t&)(*m_num_radio);
}

std::tuple<bool, cRadioEntry&> tlvEHTOperations::radioEntries(size_t idx) {
    bool ret_success = ( (m_radioEntries_idx__ > 0) && (m_radioEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_radioEntries_vector[ret_idx]));
}

std::shared_ptr<cRadioEntry> tlvEHTOperations::create_radioEntries() {
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

bool tlvEHTOperations::add_radioEntries(std::shared_ptr<cRadioEntry> ptr) {
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

void tlvEHTOperations::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_reserved));
    for (size_t i = 0; i < m_radioEntries_idx__; i++){
        std::get<1>(radioEntries(i)).class_swap();
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
    class_size += sizeof(uint32_t); // reserved
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
    m_reserved = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
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

uint8_t& cRadioEntry::num_BSS() {
    return (uint8_t&)(*m_num_BSS);
}

std::tuple<bool, cBSSEntry&> cRadioEntry::bssEntries(size_t idx) {
    bool ret_success = ( (m_bssEntries_idx__ > 0) && (m_bssEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_bssEntries_vector[ret_idx]));
}

std::shared_ptr<cBSSEntry> cRadioEntry::create_bssEntries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bssEntries, abort!";
        return nullptr;
    }
    size_t len = cBSSEntry::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_bssEntries;
    if (m_bssEntries_idx__ > 0) {
        src = (uint8_t *)m_bssEntries_vector[m_bssEntries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_reserved_2 = (uint8_t *)((uint8_t *)(m_reserved_2) + len);
    return std::make_shared<cBSSEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cRadioEntry::add_bssEntries(std::shared_ptr<cBSSEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_bssEntries was called before add_bssEntries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_bssEntries;
    if (m_bssEntries_idx__ > 0) {
        src = (uint8_t *)m_bssEntries_vector[m_bssEntries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_bssEntries_idx__++;
    if (!m_parse__) { (*m_num_BSS)++; }
    size_t len = ptr->getLen();
    m_reserved_2 = (uint8_t *)((uint8_t *)(m_reserved_2) + len - ptr->get_initial_size());
    m_bssEntries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

uint8_t* cRadioEntry::reserved_2(size_t idx) {
    if ( (m_reserved_2_idx__ == 0) || (m_reserved_2_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_2[idx]);
}

bool cRadioEntry::set_reserved_2(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_2 received a null pointer.";
        return false;
    }
    if (size > 25) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_2);
    return true;
}
void cRadioEntry::class_swap()
{
    m_ruid->struct_swap();
    for (size_t i = 0; i < m_bssEntries_idx__; i++){
        std::get<1>(bssEntries(i)).class_swap();
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
    class_size += sizeof(uint8_t); // num_BSS
    class_size += 25 * sizeof(uint8_t); // reserved_2
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
    m_num_BSS = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_BSS = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bssEntries = reinterpret_cast<cBSSEntry*>(m_buff_ptr__);
    uint8_t num_BSS = *m_num_BSS;
    m_bssEntries_idx__ = 0;
    for (size_t i = 0; i < num_BSS; i++) {
        auto bssEntries = create_bssEntries();
        if (!bssEntries || !bssEntries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_bssEntries() failed";
            return false;
        }
        if (!add_bssEntries(bssEntries)) {
            TLVF_LOG(ERROR) << "add_bssEntries() failed";
            return false;
        }
        // swap back since bssEntries will be swapped as part of the whole class swap
        bssEntries->class_swap();
    }
    m_reserved_2 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (25))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (25) << ") Failed!";
        return false;
    }
    m_reserved_2_idx__  = 25;
    if (m_parse__) { class_swap(); }
    return true;
}

cBSSEntry::cBSSEntry(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cBSSEntry::cBSSEntry(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cBSSEntry::~cBSSEntry() {
}
sMacAddr& cBSSEntry::bssid() {
    return (sMacAddr&)(*m_bssid);
}

uint8_t& cBSSEntry::EHT_Operation_Information_Valid() {
    return (uint8_t&)(*m_EHT_Operation_Information_Valid);
}

uint8_t& cBSSEntry::disabled_Subchannel_Valid() {
    return (uint8_t&)(*m_disabled_Subchannel_Valid);
}

uint8_t& cBSSEntry::EHT_Default_PE_Duration() {
    return (uint8_t&)(*m_EHT_Default_PE_Duration);
}

uint8_t& cBSSEntry::group_Addressed_BU_Indication_Limit() {
    return (uint8_t&)(*m_group_Addressed_BU_Indication_Limit);
}

uint8_t& cBSSEntry::group_Addressed_BU_Indication_Exponent() {
    return (uint8_t&)(*m_group_Addressed_BU_Indication_Exponent);
}

uint8_t& cBSSEntry::reserved() {
    return (uint8_t&)(*m_reserved);
}

uint32_t& cBSSEntry::basic_EHT_MCS_And_Nss_Set() {
    return (uint32_t&)(*m_basic_EHT_MCS_And_Nss_Set);
}

uint8_t& cBSSEntry::control() {
    return (uint8_t&)(*m_control);
}

uint8_t& cBSSEntry::ccfs0() {
    return (uint8_t&)(*m_ccfs0);
}

uint8_t& cBSSEntry::ccfs1() {
    return (uint8_t&)(*m_ccfs1);
}

uint16_t& cBSSEntry::disabled_Subchannel_Bitmap() {
    return (uint16_t&)(*m_disabled_Subchannel_Bitmap);
}

uint8_t* cBSSEntry::reserved_1(size_t idx) {
    if ( (m_reserved_1_idx__ == 0) || (m_reserved_1_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_1[idx]);
}

bool cBSSEntry::set_reserved_1(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_1 received a null pointer.";
        return false;
    }
    if (size > 16) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_1);
    return true;
}
void cBSSEntry::class_swap()
{
    m_bssid->struct_swap();
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_basic_EHT_MCS_And_Nss_Set));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_disabled_Subchannel_Bitmap));
}

bool cBSSEntry::finalize()
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

size_t cBSSEntry::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(uint8_t); // EHT_Operation_Information_Valid
    class_size += sizeof(uint8_t); // disabled_Subchannel_Valid
    class_size += sizeof(uint8_t); // EHT_Default_PE_Duration
    class_size += sizeof(uint8_t); // group_Addressed_BU_Indication_Limit
    class_size += sizeof(uint8_t); // group_Addressed_BU_Indication_Exponent
    class_size += sizeof(uint8_t); // reserved
    class_size += sizeof(uint32_t); // basic_EHT_MCS_And_Nss_Set
    class_size += sizeof(uint8_t); // control
    class_size += sizeof(uint8_t); // ccfs0
    class_size += sizeof(uint8_t); // ccfs1
    class_size += sizeof(uint16_t); // disabled_Subchannel_Bitmap
    class_size += 16 * sizeof(uint8_t); // reserved_1
    return class_size;
}

bool cBSSEntry::init()
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
    m_EHT_Operation_Information_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_disabled_Subchannel_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_EHT_Default_PE_Duration = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_group_Addressed_BU_Indication_Limit = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_group_Addressed_BU_Indication_Exponent = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_basic_EHT_MCS_And_Nss_Set = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
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
    m_disabled_Subchannel_Bitmap = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_disabled_Subchannel_Bitmap = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_reserved_1 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (16))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (16) << ") Failed!";
        return false;
    }
    m_reserved_1_idx__  = 16;
    if (m_parse__) { class_swap(); }
    return true;
}


