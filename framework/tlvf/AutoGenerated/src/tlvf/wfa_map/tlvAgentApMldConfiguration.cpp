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

#include <tlvf/wfa_map/tlvAgentApMldConfiguration.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvAgentApMldConfiguration::tlvAgentApMldConfiguration(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvAgentApMldConfiguration::tlvAgentApMldConfiguration(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvAgentApMldConfiguration::~tlvAgentApMldConfiguration() {
}
const eTlvTypeMap& tlvAgentApMldConfiguration::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvAgentApMldConfiguration::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvAgentApMldConfiguration::num_ap_mld() {
    return (uint8_t&)(*m_num_ap_mld);
}

std::tuple<bool, cApMld&> tlvAgentApMldConfiguration::ap_mld(size_t idx) {
    bool ret_success = ( (m_ap_mld_idx__ > 0) && (m_ap_mld_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_ap_mld_vector[ret_idx]));
}

std::shared_ptr<cApMld> tlvAgentApMldConfiguration::create_ap_mld() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ap_mld, abort!";
        return nullptr;
    }
    size_t len = cApMld::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_ap_mld;
    if (m_ap_mld_idx__ > 0) {
        src = (uint8_t *)m_ap_mld_vector[m_ap_mld_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cApMld>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvAgentApMldConfiguration::add_ap_mld(std::shared_ptr<cApMld> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_ap_mld was called before add_ap_mld";
        return false;
    }
    uint8_t *src = (uint8_t *)m_ap_mld;
    if (m_ap_mld_idx__ > 0) {
        src = (uint8_t *)m_ap_mld_vector[m_ap_mld_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_ap_mld_idx__++;
    if (!m_parse__) { (*m_num_ap_mld)++; }
    size_t len = ptr->getLen();
    m_ap_mld_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvAgentApMldConfiguration::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_ap_mld_idx__; i++){
        std::get<1>(ap_mld(i)).class_swap();
    }
}

bool tlvAgentApMldConfiguration::finalize()
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

size_t tlvAgentApMldConfiguration::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // num_ap_mld
    return class_size;
}

bool tlvAgentApMldConfiguration::init()
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
    m_num_ap_mld = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_ap_mld = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_ap_mld = reinterpret_cast<cApMld*>(m_buff_ptr__);
    uint8_t num_ap_mld = *m_num_ap_mld;
    m_ap_mld_idx__ = 0;
    for (size_t i = 0; i < num_ap_mld; i++) {
        auto ap_mld = create_ap_mld();
        if (!ap_mld || !ap_mld->isInitialized()) {
            TLVF_LOG(ERROR) << "create_ap_mld() failed";
            return false;
        }
        if (!add_ap_mld(ap_mld)) {
            TLVF_LOG(ERROR) << "add_ap_mld() failed";
            return false;
        }
        // swap back since ap_mld will be swapped as part of the whole class swap
        ap_mld->class_swap();
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

cApMld::cApMld(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cApMld::cApMld(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cApMld::~cApMld() {
}
cApMld::sApMldMacAddrValid& cApMld::ap_mld_mac_addr_valid() {
    return (sApMldMacAddrValid&)(*m_ap_mld_mac_addr_valid);
}

uint8_t& cApMld::ssid_length() {
    return (uint8_t&)(*m_ssid_length);
}

std::string cApMld::ssid_str() {
    char *ssid_ = ssid();
    if (!ssid_) { return std::string(); }
    auto str = std::string(ssid_, m_ssid_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cApMld::ssid(size_t length) {
    if( (m_ssid_idx__ == 0) || (m_ssid_idx__ < length) ) {
        TLVF_LOG(ERROR) << "ssid length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_ssid);
}

bool cApMld::set_ssid(const std::string& str) { return set_ssid(str.c_str(), str.size()); }
bool cApMld::set_ssid(const char str[], size_t size) {
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
bool cApMld::alloc_ssid(size_t count) {
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
    m_ap_mld_mac_addr = (sMacAddr *)((uint8_t *)(m_ap_mld_mac_addr) + len);
    m_modes = (sModes *)((uint8_t *)(m_modes) + len);
    m_reserved = (uint8_t *)((uint8_t *)(m_reserved) + len);
    m_num_affiliated_ap = (uint8_t *)((uint8_t *)(m_num_affiliated_ap) + len);
    m_affiliated_ap = (cAffiliatedAp *)((uint8_t *)(m_affiliated_ap) + len);
    m_ssid_idx__ += count;
    *m_ssid_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

sMacAddr& cApMld::ap_mld_mac_addr() {
    return (sMacAddr&)(*m_ap_mld_mac_addr);
}

cApMld::sModes& cApMld::modes() {
    return (sModes&)(*m_modes);
}

uint8_t* cApMld::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cApMld::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 20) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
uint8_t& cApMld::num_affiliated_ap() {
    return (uint8_t&)(*m_num_affiliated_ap);
}

std::tuple<bool, cAffiliatedAp&> cApMld::affiliated_ap(size_t idx) {
    bool ret_success = ( (m_affiliated_ap_idx__ > 0) && (m_affiliated_ap_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_affiliated_ap_vector[ret_idx]));
}

std::shared_ptr<cAffiliatedAp> cApMld::create_affiliated_ap() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list affiliated_ap, abort!";
        return nullptr;
    }
    size_t len = cAffiliatedAp::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_affiliated_ap;
    if (m_affiliated_ap_idx__ > 0) {
        src = (uint8_t *)m_affiliated_ap_vector[m_affiliated_ap_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cAffiliatedAp>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cApMld::add_affiliated_ap(std::shared_ptr<cAffiliatedAp> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_affiliated_ap was called before add_affiliated_ap";
        return false;
    }
    uint8_t *src = (uint8_t *)m_affiliated_ap;
    if (m_affiliated_ap_idx__ > 0) {
        src = (uint8_t *)m_affiliated_ap_vector[m_affiliated_ap_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_affiliated_ap_idx__++;
    if (!m_parse__) { (*m_num_affiliated_ap)++; }
    size_t len = ptr->getLen();
    m_affiliated_ap_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cApMld::class_swap()
{
    m_ap_mld_mac_addr_valid->struct_swap();
    m_ap_mld_mac_addr->struct_swap();
    m_modes->struct_swap();
    for (size_t i = 0; i < m_affiliated_ap_idx__; i++){
        std::get<1>(affiliated_ap(i)).class_swap();
    }
}

bool cApMld::finalize()
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

size_t cApMld::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sApMldMacAddrValid); // ap_mld_mac_addr_valid
    class_size += sizeof(uint8_t); // ssid_length
    class_size += sizeof(sMacAddr); // ap_mld_mac_addr
    class_size += sizeof(sModes); // modes
    class_size += 20 * sizeof(uint8_t); // reserved
    class_size += sizeof(uint8_t); // num_affiliated_ap
    return class_size;
}

bool cApMld::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_ap_mld_mac_addr_valid = reinterpret_cast<sApMldMacAddrValid*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sApMldMacAddrValid))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sApMldMacAddrValid) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_ap_mld_mac_addr_valid->struct_init(); }
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
    m_ap_mld_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_ap_mld_mac_addr->struct_init(); }
    m_modes = reinterpret_cast<sModes*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sModes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sModes) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_modes->struct_init(); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (20))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (20) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 20;
    m_num_affiliated_ap = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_affiliated_ap = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_affiliated_ap = reinterpret_cast<cAffiliatedAp*>(m_buff_ptr__);
    uint8_t num_affiliated_ap = *m_num_affiliated_ap;
    m_affiliated_ap_idx__ = 0;
    for (size_t i = 0; i < num_affiliated_ap; i++) {
        auto affiliated_ap = create_affiliated_ap();
        if (!affiliated_ap || !affiliated_ap->isInitialized()) {
            TLVF_LOG(ERROR) << "create_affiliated_ap() failed";
            return false;
        }
        if (!add_affiliated_ap(affiliated_ap)) {
            TLVF_LOG(ERROR) << "add_affiliated_ap() failed";
            return false;
        }
        // swap back since affiliated_ap will be swapped as part of the whole class swap
        affiliated_ap->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cAffiliatedAp::cAffiliatedAp(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cAffiliatedAp::cAffiliatedAp(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cAffiliatedAp::~cAffiliatedAp() {
}
cAffiliatedAp::sAffiliatedApFieldsValid& cAffiliatedAp::affiliated_ap_fields_valid() {
    return (sAffiliatedApFieldsValid&)(*m_affiliated_ap_fields_valid);
}

sMacAddr& cAffiliatedAp::ruid() {
    return (sMacAddr&)(*m_ruid);
}

sMacAddr& cAffiliatedAp::affiliated_ap_mac_addr() {
    return (sMacAddr&)(*m_affiliated_ap_mac_addr);
}

uint8_t& cAffiliatedAp::linkid() {
    return (uint8_t&)(*m_linkid);
}

uint8_t* cAffiliatedAp::reserved(size_t idx) {
    if ( (m_reserved_idx__ == 0) || (m_reserved_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_reserved[idx]);
}

bool cAffiliatedAp::set_reserved(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_reserved received a null pointer.";
        return false;
    }
    if (size > 18) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_reserved);
    return true;
}
void cAffiliatedAp::class_swap()
{
    m_affiliated_ap_fields_valid->struct_swap();
    m_ruid->struct_swap();
    m_affiliated_ap_mac_addr->struct_swap();
}

bool cAffiliatedAp::finalize()
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

size_t cAffiliatedAp::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sAffiliatedApFieldsValid); // affiliated_ap_fields_valid
    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sMacAddr); // affiliated_ap_mac_addr
    class_size += sizeof(uint8_t); // linkid
    class_size += 18 * sizeof(uint8_t); // reserved
    return class_size;
}

bool cAffiliatedAp::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_affiliated_ap_fields_valid = reinterpret_cast<sAffiliatedApFieldsValid*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sAffiliatedApFieldsValid))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sAffiliatedApFieldsValid) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_affiliated_ap_fields_valid->struct_init(); }
    m_ruid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_ruid->struct_init(); }
    m_affiliated_ap_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_affiliated_ap_mac_addr->struct_init(); }
    m_linkid = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (18))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (18) << ") Failed!";
        return false;
    }
    m_reserved_idx__  = 18;
    if (m_parse__) { class_swap(); }
    return true;
}


