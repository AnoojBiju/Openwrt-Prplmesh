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

#include <tlvf/wfa_map/tlvApWifi6Capabilities.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvApWifi6Capabilities::tlvApWifi6Capabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvApWifi6Capabilities::tlvApWifi6Capabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvApWifi6Capabilities::~tlvApWifi6Capabilities() {
}
const eTlvTypeMap& tlvApWifi6Capabilities::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvApWifi6Capabilities::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvApWifi6Capabilities::radio_uid() {
    return (sMacAddr&)(*m_radio_uid);
}

uint8_t& tlvApWifi6Capabilities::number_of_roles() {
    return (uint8_t&)(*m_number_of_roles);
}

std::tuple<bool, cRole&> tlvApWifi6Capabilities::role(size_t idx) {
    bool ret_success = ( (m_role_idx__ > 0) && (m_role_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_role_vector[ret_idx]));
}

std::shared_ptr<cRole> tlvApWifi6Capabilities::create_role() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list role, abort!";
        return nullptr;
    }
    size_t len = cRole::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_role;
    if (m_role_idx__ > 0) {
        src = (uint8_t *)m_role_vector[m_role_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cRole>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvApWifi6Capabilities::add_role(std::shared_ptr<cRole> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_role was called before add_role";
        return false;
    }
    uint8_t *src = (uint8_t *)m_role;
    if (m_role_idx__ > 0) {
        src = (uint8_t *)m_role_vector[m_role_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_role_idx__++;
    if (!m_parse__) { (*m_number_of_roles)++; }
    size_t len = ptr->getLen();
    m_role_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvApWifi6Capabilities::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_radio_uid->struct_swap();
    for (size_t i = 0; i < m_role_idx__; i++){
        std::get<1>(role(i)).class_swap();
    }
}

bool tlvApWifi6Capabilities::finalize()
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

size_t tlvApWifi6Capabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // radio_uid
    class_size += sizeof(uint8_t); // number_of_roles
    return class_size;
}

bool tlvApWifi6Capabilities::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_AP_WIFI_6_CAPABILITIES;
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
    m_radio_uid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_radio_uid->struct_init(); }
    m_number_of_roles = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_number_of_roles = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_role = reinterpret_cast<cRole*>(m_buff_ptr__);
    uint8_t number_of_roles = *m_number_of_roles;
    m_role_idx__ = 0;
    for (size_t i = 0; i < number_of_roles; i++) {
        auto role = create_role();
        if (!role || !role->isInitialized()) {
            TLVF_LOG(ERROR) << "create_role() failed";
            return false;
        }
        if (!add_role(role)) {
            TLVF_LOG(ERROR) << "add_role() failed";
            return false;
        }
        // swap back since role will be swapped as part of the whole class swap
        role->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_AP_WIFI_6_CAPABILITIES) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_AP_WIFI_6_CAPABILITIES) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cRole::cRole(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cRole::cRole(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cRole::~cRole() {
}
cRole::sFlags1& cRole::flags1() {
    return (sFlags1&)(*m_flags1);
}

uint32_t& cRole::mcs_nss_80() {
    return (uint32_t&)(*m_mcs_nss_80);
}

bool cRole::alloc_mcs_nss_160() {
    if (m_mcs_nss_160_allocated) {
        LOG(ERROR) << "mcs_nss_160 already allocated!";
        return false;
    }
    size_t len = sizeof(uint32_t);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_mcs_nss_160;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_mcs_nss_80_80 = (uint32_t *)((uint8_t *)(m_mcs_nss_80_80) + len);
    m_flags2 = (sFlags2 *)((uint8_t *)(m_flags2) + len);
    m_flags3 = (sFlags3 *)((uint8_t *)(m_flags3) + len);
    m_max_dl_ofdma_tx = (uint8_t *)((uint8_t *)(m_max_dl_ofdma_tx) + len);
    m_max_ul_ofdma_rx = (uint8_t *)((uint8_t *)(m_max_ul_ofdma_rx) + len);
    m_flags4 = (sFlags4 *)((uint8_t *)(m_flags4) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_mcs_nss_160_allocated = true;
    return true;
}

uint32_t* cRole::mcs_nss_160() {
    if (!m_flags1 || !(m_flags1->he_support_160mhz)) {
        TLVF_LOG(ERROR) << "mcs_nss_160 requested but condition not met: m_flags1->he_support_160mhz";
        return nullptr;
    }
    return (uint32_t*)(m_mcs_nss_160);
}

bool cRole::set_mcs_nss_160(const uint32_t mcs_nss_160) {
    if (!m_mcs_nss_160_allocated && !alloc_mcs_nss_160()) {
        LOG(ERROR) << "Could not allocate mcs_nss_160!";
        return false;
    }
    *m_mcs_nss_160 = mcs_nss_160;
    return true;
}

bool cRole::alloc_mcs_nss_80_80() {
    if (m_mcs_nss_80_80_allocated) {
        LOG(ERROR) << "mcs_nss_80_80 already allocated!";
        return false;
    }
    size_t len = sizeof(uint32_t);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_mcs_nss_80_80;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_flags2 = (sFlags2 *)((uint8_t *)(m_flags2) + len);
    m_flags3 = (sFlags3 *)((uint8_t *)(m_flags3) + len);
    m_max_dl_ofdma_tx = (uint8_t *)((uint8_t *)(m_max_dl_ofdma_tx) + len);
    m_max_ul_ofdma_rx = (uint8_t *)((uint8_t *)(m_max_ul_ofdma_rx) + len);
    m_flags4 = (sFlags4 *)((uint8_t *)(m_flags4) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_mcs_nss_80_80_allocated = true;
    return true;
}

uint32_t* cRole::mcs_nss_80_80() {
    if (!m_flags1 || !(m_flags1->he_support_80_80mhz)) {
        TLVF_LOG(ERROR) << "mcs_nss_80_80 requested but condition not met: m_flags1->he_support_80_80mhz";
        return nullptr;
    }
    return (uint32_t*)(m_mcs_nss_80_80);
}

bool cRole::set_mcs_nss_80_80(const uint32_t mcs_nss_80_80) {
    if (!m_mcs_nss_80_80_allocated && !alloc_mcs_nss_80_80()) {
        LOG(ERROR) << "Could not allocate mcs_nss_80_80!";
        return false;
    }
    *m_mcs_nss_80_80 = mcs_nss_80_80;
    return true;
}

cRole::sFlags2& cRole::flags2() {
    return (sFlags2&)(*m_flags2);
}

cRole::sFlags3& cRole::flags3() {
    return (sFlags3&)(*m_flags3);
}

uint8_t& cRole::max_dl_ofdma_tx() {
    return (uint8_t&)(*m_max_dl_ofdma_tx);
}

uint8_t& cRole::max_ul_ofdma_rx() {
    return (uint8_t&)(*m_max_ul_ofdma_rx);
}

cRole::sFlags4& cRole::flags4() {
    return (sFlags4&)(*m_flags4);
}

void cRole::class_swap()
{
    m_flags1->struct_swap();
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_mcs_nss_80));
    if (m_flags1->he_support_160mhz) {
        tlvf_swap(32, reinterpret_cast<uint8_t*>(m_mcs_nss_160));
    }
    if (m_flags1->he_support_80_80mhz) {
        tlvf_swap(32, reinterpret_cast<uint8_t*>(m_mcs_nss_80_80));
    }
    m_flags2->struct_swap();
    m_flags3->struct_swap();
    m_flags4->struct_swap();
}

bool cRole::finalize()
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

size_t cRole::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sFlags1); // flags1
    class_size += sizeof(uint32_t); // mcs_nss_80
    class_size += sizeof(sFlags2); // flags2
    class_size += sizeof(sFlags3); // flags3
    class_size += sizeof(uint8_t); // max_dl_ofdma_tx
    class_size += sizeof(uint8_t); // max_ul_ofdma_rx
    class_size += sizeof(sFlags4); // flags4
    return class_size;
}

bool cRole::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_flags1 = reinterpret_cast<sFlags1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags1) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags1->struct_init(); }
    m_mcs_nss_80 = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    m_mcs_nss_160 = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if ((m_flags1->he_support_160mhz) && !buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    m_mcs_nss_80_80 = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if ((m_flags1->he_support_80_80mhz) && !buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    m_flags2 = reinterpret_cast<sFlags2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags2) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags2->struct_init(); }
    m_flags3 = reinterpret_cast<sFlags3*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags3))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags3) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags3->struct_init(); }
    m_max_dl_ofdma_tx = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_max_dl_ofdma_tx = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_max_ul_ofdma_rx = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_max_ul_ofdma_rx = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_flags4 = reinterpret_cast<sFlags4*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags4))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags4) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_flags4->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}


