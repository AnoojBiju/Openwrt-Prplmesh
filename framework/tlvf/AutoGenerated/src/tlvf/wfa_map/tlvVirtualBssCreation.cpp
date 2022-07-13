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

#include <tlvf/wfa_map/tlvVirtualBssCreation.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

VirtualBssCreation::VirtualBssCreation(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
VirtualBssCreation::VirtualBssCreation(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
VirtualBssCreation::~VirtualBssCreation() {
}
const eTlvTypeMap& VirtualBssCreation::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& VirtualBssCreation::length() {
    return (const uint16_t&)(*m_length);
}

const eVirtualBssSubtype& VirtualBssCreation::subtype() {
    return (const eVirtualBssSubtype&)(*m_subtype);
}

sMacAddr& VirtualBssCreation::radio_uid() {
    return (sMacAddr&)(*m_radio_uid);
}

sMacAddr& VirtualBssCreation::bssid() {
    return (sMacAddr&)(*m_bssid);
}

uint16_t& VirtualBssCreation::ssid_length() {
    return (uint16_t&)(*m_ssid_length);
}

std::string VirtualBssCreation::ssid_str() {
    char *ssid_ = ssid();
    if (!ssid_) { return std::string(); }
    auto str = std::string(ssid_, m_ssid_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* VirtualBssCreation::ssid(size_t length) {
    if( (m_ssid_idx__ == 0) || (m_ssid_idx__ < length) ) {
        TLVF_LOG(ERROR) << "ssid length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_ssid);
}

bool VirtualBssCreation::set_ssid(const std::string& str) { return set_ssid(str.c_str(), str.size()); }
bool VirtualBssCreation::set_ssid(const char str[], size_t size) {
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
bool VirtualBssCreation::alloc_ssid(size_t count) {
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
    m_pass_length = (uint16_t *)((uint8_t *)(m_pass_length) + len);
    m_pass = (char *)((uint8_t *)(m_pass) + len);
    m_dpp_connector_length = (uint16_t *)((uint8_t *)(m_dpp_connector_length) + len);
    m_dpp_connector = (char *)((uint8_t *)(m_dpp_connector) + len);
    m_client_mac = (sMacAddr *)((uint8_t *)(m_client_mac) + len);
    m_client_assoc = (uint8_t *)((uint8_t *)(m_client_assoc) + len);
    m_key_length = (uint16_t *)((uint8_t *)(m_key_length) + len);
    m_ptk = (uint8_t *)((uint8_t *)(m_ptk) + len);
    m_tx_packet_num = (uint64_t *)((uint8_t *)(m_tx_packet_num) + len);
    m_group_key_length = (uint16_t *)((uint8_t *)(m_group_key_length) + len);
    m_gtk = (uint8_t *)((uint8_t *)(m_gtk) + len);
    m_group_tx_packet_num = (uint64_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_ssid_idx__ += count;
    *m_ssid_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint16_t& VirtualBssCreation::pass_length() {
    return (uint16_t&)(*m_pass_length);
}

std::string VirtualBssCreation::pass_str() {
    char *pass_ = pass();
    if (!pass_) { return std::string(); }
    auto str = std::string(pass_, m_pass_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* VirtualBssCreation::pass(size_t length) {
    if( (m_pass_idx__ == 0) || (m_pass_idx__ < length) ) {
        TLVF_LOG(ERROR) << "pass length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_pass);
}

bool VirtualBssCreation::set_pass(const std::string& str) { return set_pass(str.c_str(), str.size()); }
bool VirtualBssCreation::set_pass(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_pass received a null pointer.";
        return false;
    }
    if (m_pass_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_pass was already allocated!";
        return false;
    }
    if (!alloc_pass(size)) { return false; }
    std::copy(str, str + size, m_pass);
    return true;
}
bool VirtualBssCreation::alloc_pass(size_t count) {
    if (m_lock_order_counter__ > 1) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list pass, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 1;
    uint8_t *src = (uint8_t *)&m_pass[*m_pass_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_dpp_connector_length = (uint16_t *)((uint8_t *)(m_dpp_connector_length) + len);
    m_dpp_connector = (char *)((uint8_t *)(m_dpp_connector) + len);
    m_client_mac = (sMacAddr *)((uint8_t *)(m_client_mac) + len);
    m_client_assoc = (uint8_t *)((uint8_t *)(m_client_assoc) + len);
    m_key_length = (uint16_t *)((uint8_t *)(m_key_length) + len);
    m_ptk = (uint8_t *)((uint8_t *)(m_ptk) + len);
    m_tx_packet_num = (uint64_t *)((uint8_t *)(m_tx_packet_num) + len);
    m_group_key_length = (uint16_t *)((uint8_t *)(m_group_key_length) + len);
    m_gtk = (uint8_t *)((uint8_t *)(m_gtk) + len);
    m_group_tx_packet_num = (uint64_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_pass_idx__ += count;
    *m_pass_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint16_t& VirtualBssCreation::dpp_connector_length() {
    return (uint16_t&)(*m_dpp_connector_length);
}

std::string VirtualBssCreation::dpp_connector_str() {
    char *dpp_connector_ = dpp_connector();
    if (!dpp_connector_) { return std::string(); }
    auto str = std::string(dpp_connector_, m_dpp_connector_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* VirtualBssCreation::dpp_connector(size_t length) {
    if( (m_dpp_connector_idx__ == 0) || (m_dpp_connector_idx__ < length) ) {
        TLVF_LOG(ERROR) << "dpp_connector length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_dpp_connector);
}

bool VirtualBssCreation::set_dpp_connector(const std::string& str) { return set_dpp_connector(str.c_str(), str.size()); }
bool VirtualBssCreation::set_dpp_connector(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_dpp_connector received a null pointer.";
        return false;
    }
    if (m_dpp_connector_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_dpp_connector was already allocated!";
        return false;
    }
    if (!alloc_dpp_connector(size)) { return false; }
    std::copy(str, str + size, m_dpp_connector);
    return true;
}
bool VirtualBssCreation::alloc_dpp_connector(size_t count) {
    if (m_lock_order_counter__ > 2) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list dpp_connector, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 2;
    uint8_t *src = (uint8_t *)&m_dpp_connector[*m_dpp_connector_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_client_mac = (sMacAddr *)((uint8_t *)(m_client_mac) + len);
    m_client_assoc = (uint8_t *)((uint8_t *)(m_client_assoc) + len);
    m_key_length = (uint16_t *)((uint8_t *)(m_key_length) + len);
    m_ptk = (uint8_t *)((uint8_t *)(m_ptk) + len);
    m_tx_packet_num = (uint64_t *)((uint8_t *)(m_tx_packet_num) + len);
    m_group_key_length = (uint16_t *)((uint8_t *)(m_group_key_length) + len);
    m_gtk = (uint8_t *)((uint8_t *)(m_gtk) + len);
    m_group_tx_packet_num = (uint64_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_dpp_connector_idx__ += count;
    *m_dpp_connector_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

sMacAddr& VirtualBssCreation::client_mac() {
    return (sMacAddr&)(*m_client_mac);
}

uint8_t& VirtualBssCreation::client_assoc() {
    return (uint8_t&)(*m_client_assoc);
}

uint16_t& VirtualBssCreation::key_length() {
    return (uint16_t&)(*m_key_length);
}

uint8_t* VirtualBssCreation::ptk(size_t idx) {
    if ( (m_ptk_idx__ == 0) || (m_ptk_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_ptk[idx]);
}

bool VirtualBssCreation::set_ptk(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_ptk received a null pointer.";
        return false;
    }
    if (m_ptk_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_ptk was already allocated!";
        return false;
    }
    if (!alloc_ptk(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_ptk);
    return true;
}
bool VirtualBssCreation::alloc_ptk(size_t count) {
    if (m_lock_order_counter__ > 3) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ptk, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 3;
    uint8_t *src = (uint8_t *)&m_ptk[*m_key_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_tx_packet_num = (uint64_t *)((uint8_t *)(m_tx_packet_num) + len);
    m_group_key_length = (uint16_t *)((uint8_t *)(m_group_key_length) + len);
    m_gtk = (uint8_t *)((uint8_t *)(m_gtk) + len);
    m_group_tx_packet_num = (uint64_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_ptk_idx__ += count;
    *m_key_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint64_t& VirtualBssCreation::tx_packet_num() {
    return (uint64_t&)(*m_tx_packet_num);
}

uint16_t& VirtualBssCreation::group_key_length() {
    return (uint16_t&)(*m_group_key_length);
}

uint8_t* VirtualBssCreation::gtk(size_t idx) {
    if ( (m_gtk_idx__ == 0) || (m_gtk_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_gtk[idx]);
}

bool VirtualBssCreation::set_gtk(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_gtk received a null pointer.";
        return false;
    }
    if (m_gtk_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_gtk was already allocated!";
        return false;
    }
    if (!alloc_gtk(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_gtk);
    return true;
}
bool VirtualBssCreation::alloc_gtk(size_t count) {
    if (m_lock_order_counter__ > 4) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list gtk, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 4;
    uint8_t *src = (uint8_t *)&m_gtk[*m_group_key_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_group_tx_packet_num = (uint64_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_gtk_idx__ += count;
    *m_group_key_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint64_t& VirtualBssCreation::group_tx_packet_num() {
    return (uint64_t&)(*m_group_tx_packet_num);
}

void VirtualBssCreation::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_subtype));
    m_radio_uid->struct_swap();
    m_bssid->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_ssid_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_pass_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_dpp_connector_length));
    m_client_mac->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_key_length));
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_tx_packet_num));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_group_key_length));
    tlvf_swap(64, reinterpret_cast<uint8_t*>(m_group_tx_packet_num));
}

bool VirtualBssCreation::finalize()
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

size_t VirtualBssCreation::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(eVirtualBssSubtype); // subtype
    class_size += sizeof(sMacAddr); // radio_uid
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(uint16_t); // ssid_length
    class_size += sizeof(uint16_t); // pass_length
    class_size += sizeof(uint16_t); // dpp_connector_length
    class_size += sizeof(sMacAddr); // client_mac
    class_size += sizeof(uint8_t); // client_assoc
    class_size += sizeof(uint16_t); // key_length
    class_size += sizeof(uint64_t); // tx_packet_num
    class_size += sizeof(uint16_t); // group_key_length
    class_size += sizeof(uint64_t); // group_tx_packet_num
    return class_size;
}

bool VirtualBssCreation::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_VIRTUAL_BSS;
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
    m_subtype = reinterpret_cast<eVirtualBssSubtype*>(m_buff_ptr__);
    if (!m_parse__) *m_subtype = eVirtualBssSubtype::VIRTUAL_BSS_CREATION;
    if (!buffPtrIncrementSafe(sizeof(eVirtualBssSubtype))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eVirtualBssSubtype) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eVirtualBssSubtype); }
    m_radio_uid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_radio_uid->struct_init(); }
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_ssid_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_ssid_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_ssid = reinterpret_cast<char*>(m_buff_ptr__);
    uint16_t ssid_length = *m_ssid_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&ssid_length)); }
    m_ssid_idx__ = ssid_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (ssid_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (ssid_length) << ") Failed!";
        return false;
    }
    m_pass_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_pass_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_pass = reinterpret_cast<char*>(m_buff_ptr__);
    uint16_t pass_length = *m_pass_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&pass_length)); }
    m_pass_idx__ = pass_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (pass_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (pass_length) << ") Failed!";
        return false;
    }
    m_dpp_connector_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_dpp_connector_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_dpp_connector = reinterpret_cast<char*>(m_buff_ptr__);
    uint16_t dpp_connector_length = *m_dpp_connector_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&dpp_connector_length)); }
    m_dpp_connector_idx__ = dpp_connector_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (dpp_connector_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (dpp_connector_length) << ") Failed!";
        return false;
    }
    m_client_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_client_mac->struct_init(); }
    m_client_assoc = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_key_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_key_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_ptk = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    uint16_t key_length = *m_key_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&key_length)); }
    m_ptk_idx__ = key_length;
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (key_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (key_length) << ") Failed!";
        return false;
    }
    m_tx_packet_num = reinterpret_cast<uint64_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint64_t); }
    m_group_key_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_group_key_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_gtk = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    uint16_t group_key_length = *m_group_key_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&group_key_length)); }
    m_gtk_idx__ = group_key_length;
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (group_key_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (group_key_length) << ") Failed!";
        return false;
    }
    m_group_tx_packet_num = reinterpret_cast<uint64_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint64_t); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_VIRTUAL_BSS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_VIRTUAL_BSS) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


