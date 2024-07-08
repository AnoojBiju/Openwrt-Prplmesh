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

#include <tlvf/wfa_map/tlvAgentApMLDconfiguration.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvAgentApMLDconfiguration::tlvAgentApMLDconfiguration(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvAgentApMLDconfiguration::tlvAgentApMLDconfiguration(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvAgentApMLDconfiguration::~tlvAgentApMLDconfiguration() {
}
const eTlvTypeMap& tlvAgentApMLDconfiguration::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvAgentApMLDconfiguration::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvAgentApMLDconfiguration::num_APMLD() {
    return (uint8_t&)(*m_num_APMLD);
}

std::tuple<bool, cAPMLDEntry&> tlvAgentApMLDconfiguration::apMLDEntries(size_t idx) {
    bool ret_success = ( (m_apMLDEntries_idx__ > 0) && (m_apMLDEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_apMLDEntries_vector[ret_idx]));
}

std::shared_ptr<cAPMLDEntry> tlvAgentApMLDconfiguration::create_apMLDEntries() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list apMLDEntries, abort!";
        return nullptr;
    }
    size_t len = cAPMLDEntry::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_apMLDEntries;
    if (m_apMLDEntries_idx__ > 0) {
        src = (uint8_t *)m_apMLDEntries_vector[m_apMLDEntries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cAPMLDEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvAgentApMLDconfiguration::add_apMLDEntries(std::shared_ptr<cAPMLDEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_apMLDEntries was called before add_apMLDEntries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_apMLDEntries;
    if (m_apMLDEntries_idx__ > 0) {
        src = (uint8_t *)m_apMLDEntries_vector[m_apMLDEntries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_apMLDEntries_idx__++;
    if (!m_parse__) { (*m_num_APMLD)++; }
    size_t len = ptr->getLen();
    m_apMLDEntries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvAgentApMLDconfiguration::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_apMLDEntries_idx__; i++){
        std::get<1>(apMLDEntries(i)).class_swap();
    }
}

bool tlvAgentApMLDconfiguration::finalize()
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

size_t tlvAgentApMLDconfiguration::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // num_APMLD
    return class_size;
}

bool tlvAgentApMLDconfiguration::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_AGENT_AP_MLD_CONFIGURATION;
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
    m_num_APMLD = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_APMLD = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_apMLDEntries = reinterpret_cast<cAPMLDEntry*>(m_buff_ptr__);
    uint8_t num_APMLD = *m_num_APMLD;
    m_apMLDEntries_idx__ = 0;
    for (size_t i = 0; i < num_APMLD; i++) {
        auto apMLDEntries = create_apMLDEntries();
        if (!apMLDEntries || !apMLDEntries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_apMLDEntries() failed";
            return false;
        }
        if (!add_apMLDEntries(apMLDEntries)) {
            TLVF_LOG(ERROR) << "add_apMLDEntries() failed";
            return false;
        }
        // swap back since apMLDEntries will be swapped as part of the whole class swap
        apMLDEntries->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_AGENT_AP_MLD_CONFIGURATION) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_AGENT_AP_MLD_CONFIGURATION) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cAPMLDEntry::cAPMLDEntry(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAPMLDEntry::cAPMLDEntry(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAPMLDEntry::~cAPMLDEntry() {
}
uint8_t& cAPMLDEntry::AP_MLD_MAC_Addr_Valid() {
    return (uint8_t&)(*m_AP_MLD_MAC_Addr_Valid);
}

uint8_t& cAPMLDEntry::reserved_1() {
    return (uint8_t&)(*m_reserved_1);
}

uint8_t& cAPMLDEntry::ssid_length() {
    return (uint8_t&)(*m_ssid_length);
}

std::string cAPMLDEntry::ssid_str() {
    char *ssid_ = ssid();
    if (!ssid_) { return std::string(); }
    auto str = std::string(ssid_, m_ssid_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cAPMLDEntry::ssid(size_t length) {
    if( (m_ssid_idx__ == 0) || (m_ssid_idx__ < length) ) {
        TLVF_LOG(ERROR) << "ssid length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_ssid);
}

bool cAPMLDEntry::set_ssid(const std::string& str) { return set_ssid(str.c_str(), str.size()); }
bool cAPMLDEntry::set_ssid(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_ssid received a null pointer.";
        return false;
    }
    if (m_ssid_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_ssid was already allocated!";
        return false;
    }
    if (!alloc_ssid(size)) { return false; }
    std::copy(str, str + size, m_ssid);
    return true;
}
bool cAPMLDEntry::alloc_ssid(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ssid, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_ssid[*m_ssid_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_AP_MLD_MAC_Addr = (sMacAddr *)((uint8_t *)(m_AP_MLD_MAC_Addr) + len);
    m_STR = (uint8_t *)((uint8_t *)(m_STR) + len);
    m_NSTR = (uint8_t *)((uint8_t *)(m_NSTR) + len);
    m_EMLSR = (uint8_t *)((uint8_t *)(m_EMLSR) + len);
    m_EMLMR = (uint8_t *)((uint8_t *)(m_EMLMR) + len);
    m_reserved_2 = (uint8_t *)((uint8_t *)(m_reserved_2) + len);
    m_reserved_3 = (uint8_t *)((uint8_t *)(m_reserved_3) + len);
    m_num_AffiliatedAP = (uint8_t *)((uint8_t *)(m_num_AffiliatedAP) + len);
    m_affiliatedAPEntries = (cAffiliatedAPEntry *)((uint8_t *)(m_affiliatedAPEntries) + len);
    m_ssid_idx__ += count;
    *m_ssid_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

sMacAddr& cAPMLDEntry::AP_MLD_MAC_Addr() {
    return (sMacAddr&)(*m_AP_MLD_MAC_Addr);
}

uint8_t& cAPMLDEntry::STR() {
    return (uint8_t&)(*m_STR);
}

uint8_t& cAPMLDEntry::NSTR() {
    return (uint8_t&)(*m_NSTR);
}

uint8_t& cAPMLDEntry::EMLSR() {
    return (uint8_t&)(*m_EMLSR);
}

uint8_t& cAPMLDEntry::EMLMR() {
    return (uint8_t&)(*m_EMLMR);
}

uint8_t& cAPMLDEntry::reserved_2() {
    return (uint8_t&)(*m_reserved_2);
}

uint8_t* cAPMLDEntry::reserved_3(size_t idx) {
    if ( (m_reserved_3_idx__ == 0) || (m_reserved_3_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved_3[idx]);
}

bool cAPMLDEntry::set_reserved_3(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved_3 received a null pointer.";
        return false;
    }
    if (size > 20) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved_3);
    return true;
}
uint8_t& cAPMLDEntry::num_AffiliatedAP() {
    return (uint8_t&)(*m_num_AffiliatedAP);
}

std::tuple<bool, cAffiliatedAPEntry&> cAPMLDEntry::affiliatedAPEntries(size_t idx) {
    bool ret_success = ( (m_affiliatedAPEntries_idx__ > 0) && (m_affiliatedAPEntries_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_affiliatedAPEntries_vector[ret_idx]));
}

std::shared_ptr<cAffiliatedAPEntry> cAPMLDEntry::create_affiliatedAPEntries() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list affiliatedAPEntries, abort!";
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
    m_lock_order_counter__ = 1;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_affiliatedAPEntries;
    if (m_affiliatedAPEntries_idx__ > 0) {
        src = (uint8_t *)m_affiliatedAPEntries_vector[m_affiliatedAPEntries_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cAffiliatedAPEntry>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cAPMLDEntry::add_affiliatedAPEntries(std::shared_ptr<cAffiliatedAPEntry> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_affiliatedAPEntries was called before add_affiliatedAPEntries";
        return false;
    }
    uint8_t *src = (uint8_t *)m_affiliatedAPEntries;
    if (m_affiliatedAPEntries_idx__ > 0) {
        src = (uint8_t *)m_affiliatedAPEntries_vector[m_affiliatedAPEntries_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_affiliatedAPEntries_idx__++;
    if (!m_parse__) { (*m_num_AffiliatedAP)++; }
    size_t len = ptr->getLen();
    m_affiliatedAPEntries_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cAPMLDEntry::class_swap()
{
    m_AP_MLD_MAC_Addr->struct_swap();
    for (size_t i = 0; i < m_affiliatedAPEntries_idx__; i++){
        std::get<1>(affiliatedAPEntries(i)).class_swap();
    }
}

bool cAPMLDEntry::finalize()
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

size_t cAPMLDEntry::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // AP_MLD_MAC_Addr_Valid
    class_size += sizeof(uint8_t); // reserved_1
    class_size += sizeof(uint8_t); // ssid_length
    class_size += sizeof(sMacAddr); // AP_MLD_MAC_Addr
    class_size += sizeof(uint8_t); // STR
    class_size += sizeof(uint8_t); // NSTR
    class_size += sizeof(uint8_t); // EMLSR
    class_size += sizeof(uint8_t); // EMLMR
    class_size += sizeof(uint8_t); // reserved_2
    class_size += 20 * sizeof(uint8_t); // reserved_3
    class_size += sizeof(uint8_t); // num_AffiliatedAP
    return class_size;
}

bool cAPMLDEntry::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_AP_MLD_MAC_Addr_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_1 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_ssid_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_ssid_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_ssid = reinterpret_cast<char*>(m_buff_ptr__);
    uint8_t ssid_length = *m_ssid_length;
    m_ssid_idx__ = ssid_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (ssid_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (ssid_length) << ") Failed!";
        return false;
    }
    m_AP_MLD_MAC_Addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_AP_MLD_MAC_Addr->struct_init(); }
    m_STR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_NSTR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_EMLSR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_EMLMR = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_2 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_3 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (20))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (20) << ") Failed!";
        return false;
    }
    m_reserved_3_idx__  = 20;
    m_num_AffiliatedAP = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_AffiliatedAP = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_affiliatedAPEntries = reinterpret_cast<cAffiliatedAPEntry*>(m_buff_ptr__);
    uint8_t num_AffiliatedAP = *m_num_AffiliatedAP;
    m_affiliatedAPEntries_idx__ = 0;
    for (size_t i = 0; i < num_AffiliatedAP; i++) {
        auto affiliatedAPEntries = create_affiliatedAPEntries();
        if (!affiliatedAPEntries || !affiliatedAPEntries->isInitialized()) {
            TLVF_LOG(ERROR) << "create_affiliatedAPEntries() failed";
            return false;
        }
        if (!add_affiliatedAPEntries(affiliatedAPEntries)) {
            TLVF_LOG(ERROR) << "add_affiliatedAPEntries() failed";
            return false;
        }
        // swap back since affiliatedAPEntries will be swapped as part of the whole class swap
        affiliatedAPEntries->class_swap();
    }
    if (m_parse__) { class_swap(); }
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
uint8_t& cAffiliatedAPEntry::affiliated_AP_MAC_Addr_Valid() {
    return (uint8_t&)(*m_affiliated_AP_MAC_Addr_Valid);
}

uint8_t& cAffiliatedAPEntry::linkid_Valid() {
    return (uint8_t&)(*m_linkid_Valid);
}

uint8_t& cAffiliatedAPEntry::reserved_2() {
    return (uint8_t&)(*m_reserved_2);
}

sMacAddr& cAffiliatedAPEntry::ruid() {
    return (sMacAddr&)(*m_ruid);
}

sMacAddr& cAffiliatedAPEntry::affiliated_AP_MAC_Addr() {
    return (sMacAddr&)(*m_affiliated_AP_MAC_Addr);
}

uint8_t& cAffiliatedAPEntry::linkid() {
    return (uint8_t&)(*m_linkid);
}

uint8_t& cAffiliatedAPEntry::reserved_4() {
    return (uint8_t&)(*m_reserved_4);
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
    if (size > 18) {
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
    class_size += sizeof(uint8_t); // affiliated_AP_MAC_Addr_Valid
    class_size += sizeof(uint8_t); // linkid_Valid
    class_size += sizeof(uint8_t); // reserved_2
    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sMacAddr); // affiliated_AP_MAC_Addr
    class_size += sizeof(uint8_t); // linkid
    class_size += sizeof(uint8_t); // reserved_4
    class_size += 18 * sizeof(uint8_t); // reserved_5
    return class_size;
}

bool cAffiliatedAPEntry::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_affiliated_AP_MAC_Addr_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_linkid_Valid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_2 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
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
    m_linkid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_4 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved_5 = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (18))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (18) << ") Failed!";
        return false;
    }
    m_reserved_5_idx__  = 18;
    if (m_parse__) { class_swap(); }
    return true;
}


