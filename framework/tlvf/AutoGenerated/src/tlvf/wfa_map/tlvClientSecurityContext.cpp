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

#include <tlvf/wfa_map/tlvClientSecurityContext.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

ClientSecurityContext::ClientSecurityContext(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
ClientSecurityContext::ClientSecurityContext(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
ClientSecurityContext::~ClientSecurityContext() {
}
const eTlvTypeMap& ClientSecurityContext::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& ClientSecurityContext::length() {
    return (const uint16_t&)(*m_length);
}

const eVirtualBssSubtype& ClientSecurityContext::subtype() {
    return (const eVirtualBssSubtype&)(*m_subtype);
}

ClientSecurityContext::sClientConnectedFlags& ClientSecurityContext::client_connected_flags() {
    return (ClientSecurityContext::sClientConnectedFlags&)(*m_client_connected_flags);
}

uint16_t& ClientSecurityContext::key_length() {
    return (uint16_t&)(*m_key_length);
}

uint8_t* ClientSecurityContext::ptk(size_t idx) {
    if ( (m_ptk_idx__ == 0) || (m_ptk_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_ptk[idx]);
}

bool ClientSecurityContext::set_ptk(const void* buffer, size_t size) {
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
bool ClientSecurityContext::alloc_ptk(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ptk, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_ptk[*m_key_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_tx_pn_length = (uint16_t *)((uint8_t *)(m_tx_pn_length) + len);
    m_tx_packet_num = (uint8_t *)((uint8_t *)(m_tx_packet_num) + len);
    m_group_key_length = (uint16_t *)((uint8_t *)(m_group_key_length) + len);
    m_gtk = (uint8_t *)((uint8_t *)(m_gtk) + len);
    m_group_tx_pn_length = (uint16_t *)((uint8_t *)(m_group_tx_pn_length) + len);
    m_group_tx_packet_num = (uint8_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_ptk_idx__ += count;
    *m_key_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint16_t& ClientSecurityContext::tx_pn_length() {
    return (uint16_t&)(*m_tx_pn_length);
}

uint8_t* ClientSecurityContext::tx_packet_num(size_t idx) {
    if ( (m_tx_packet_num_idx__ == 0) || (m_tx_packet_num_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_tx_packet_num[idx]);
}

bool ClientSecurityContext::set_tx_packet_num(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_tx_packet_num received a null pointer.";
        return false;
    }
    if (m_tx_packet_num_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_tx_packet_num was already allocated!";
        return false;
    }
    if (!alloc_tx_packet_num(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_tx_packet_num);
    return true;
}
bool ClientSecurityContext::alloc_tx_packet_num(size_t count) {
    if (m_lock_order_counter__ > 1) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list tx_packet_num, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 1;
    uint8_t *src = (uint8_t *)&m_tx_packet_num[*m_tx_pn_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_group_key_length = (uint16_t *)((uint8_t *)(m_group_key_length) + len);
    m_gtk = (uint8_t *)((uint8_t *)(m_gtk) + len);
    m_group_tx_pn_length = (uint16_t *)((uint8_t *)(m_group_tx_pn_length) + len);
    m_group_tx_packet_num = (uint8_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_tx_packet_num_idx__ += count;
    *m_tx_pn_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint16_t& ClientSecurityContext::group_key_length() {
    return (uint16_t&)(*m_group_key_length);
}

uint8_t* ClientSecurityContext::gtk(size_t idx) {
    if ( (m_gtk_idx__ == 0) || (m_gtk_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_gtk[idx]);
}

bool ClientSecurityContext::set_gtk(const void* buffer, size_t size) {
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
bool ClientSecurityContext::alloc_gtk(size_t count) {
    if (m_lock_order_counter__ > 2) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list gtk, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 2;
    uint8_t *src = (uint8_t *)&m_gtk[*m_group_key_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_group_tx_pn_length = (uint16_t *)((uint8_t *)(m_group_tx_pn_length) + len);
    m_group_tx_packet_num = (uint8_t *)((uint8_t *)(m_group_tx_packet_num) + len);
    m_gtk_idx__ += count;
    *m_group_key_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint16_t& ClientSecurityContext::group_tx_pn_length() {
    return (uint16_t&)(*m_group_tx_pn_length);
}

uint8_t* ClientSecurityContext::group_tx_packet_num(size_t idx) {
    if ( (m_group_tx_packet_num_idx__ == 0) || (m_group_tx_packet_num_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_group_tx_packet_num[idx]);
}

bool ClientSecurityContext::set_group_tx_packet_num(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_group_tx_packet_num received a null pointer.";
        return false;
    }
    if (m_group_tx_packet_num_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_group_tx_packet_num was already allocated!";
        return false;
    }
    if (!alloc_group_tx_packet_num(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_group_tx_packet_num);
    return true;
}
bool ClientSecurityContext::alloc_group_tx_packet_num(size_t count) {
    if (m_lock_order_counter__ > 3) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list group_tx_packet_num, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 3;
    uint8_t *src = (uint8_t *)&m_group_tx_packet_num[*m_group_tx_pn_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_group_tx_packet_num_idx__ += count;
    *m_group_tx_pn_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void ClientSecurityContext::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_subtype));
    m_client_connected_flags->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_key_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_tx_pn_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_group_key_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_group_tx_pn_length));
}

bool ClientSecurityContext::finalize()
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

size_t ClientSecurityContext::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(eVirtualBssSubtype); // subtype
    class_size += sizeof(ClientSecurityContext::sClientConnectedFlags); // client_connected_flags
    class_size += sizeof(uint16_t); // key_length
    class_size += sizeof(uint16_t); // tx_pn_length
    class_size += sizeof(uint16_t); // group_key_length
    class_size += sizeof(uint16_t); // group_tx_pn_length
    return class_size;
}

bool ClientSecurityContext::init()
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
    if (!m_parse__) *m_subtype = eVirtualBssSubtype::CLIENT_SECURITY_CONTEXT;
    if (!buffPtrIncrementSafe(sizeof(eVirtualBssSubtype))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eVirtualBssSubtype) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eVirtualBssSubtype); }
    m_client_connected_flags = reinterpret_cast<ClientSecurityContext::sClientConnectedFlags*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(ClientSecurityContext::sClientConnectedFlags))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(ClientSecurityContext::sClientConnectedFlags) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(ClientSecurityContext::sClientConnectedFlags); }
    if (!m_parse__) { m_client_connected_flags->struct_init(); }
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
    m_tx_pn_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_tx_pn_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_tx_packet_num = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    uint16_t tx_pn_length = *m_tx_pn_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&tx_pn_length)); }
    m_tx_packet_num_idx__ = tx_pn_length;
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (tx_pn_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (tx_pn_length) << ") Failed!";
        return false;
    }
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
    m_group_tx_pn_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_group_tx_pn_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_group_tx_packet_num = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    uint16_t group_tx_pn_length = *m_group_tx_pn_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&group_tx_pn_length)); }
    m_group_tx_packet_num_idx__ = group_tx_pn_length;
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (group_tx_pn_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (group_tx_pn_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_VIRTUAL_BSS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_VIRTUAL_BSS) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


