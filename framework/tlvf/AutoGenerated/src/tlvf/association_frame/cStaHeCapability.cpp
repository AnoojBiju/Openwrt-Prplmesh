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

#include <tlvf/association_frame/cStaHeCapability.h>
#include <tlvf/tlvflogging.h>

using namespace assoc_frame;

cStaHeCapability::cStaHeCapability(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cStaHeCapability::cStaHeCapability(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cStaHeCapability::~cStaHeCapability() {
}
eElementID& cStaHeCapability::type() {
    return (eElementID&)(*m_type);
}

const uint8_t& cStaHeCapability::length() {
    return (const uint8_t&)(*m_length);
}

eExtElementID& cStaHeCapability::subtype() {
    return (eExtElementID&)(*m_subtype);
}

assoc_frame::sStaHeMacCapInfo1& cStaHeCapability::mac_cap_info1() {
    return (assoc_frame::sStaHeMacCapInfo1&)(*m_mac_cap_info1);
}

assoc_frame::sStaHeMacCapInfo2& cStaHeCapability::mac_cap_info2() {
    return (assoc_frame::sStaHeMacCapInfo2&)(*m_mac_cap_info2);
}

cStaHeCapability::sStaHePhyCapInfoB1& cStaHeCapability::supported_channel_width_set() {
    return (sStaHePhyCapInfoB1&)(*m_supported_channel_width_set);
}

assoc_frame::sStaHePhyCapInfo1& cStaHeCapability::phy_cap_info1() {
    return (assoc_frame::sStaHePhyCapInfo1&)(*m_phy_cap_info1);
}

assoc_frame::sStaHePhyCapInfo2& cStaHeCapability::phy_cap_info2() {
    return (assoc_frame::sStaHePhyCapInfo2&)(*m_phy_cap_info2);
}

uint16_t& cStaHeCapability::rx_mcs_le_80() {
    return (uint16_t&)(*m_rx_mcs_le_80);
}

uint16_t& cStaHeCapability::tx_mcs_le_80() {
    return (uint16_t&)(*m_tx_mcs_le_80);
}

bool cStaHeCapability::alloc_rx_mcs_160() {
    if (m_rx_mcs_160_allocated) {
        LOG(ERROR) << "rx_mcs_160 already allocated!";
        return false;
    }
    size_t len = sizeof(uint16_t);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_rx_mcs_160;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_tx_mcs_160 = (uint16_t *)((uint8_t *)(m_tx_mcs_160) + len);
    m_rx_mcs_80_80 = (uint16_t *)((uint8_t *)(m_rx_mcs_80_80) + len);
    m_tx_mcs_80_80 = (uint16_t *)((uint8_t *)(m_tx_mcs_80_80) + len);
    m_ppe_thresholds = (uint8_t *)((uint8_t *)(m_ppe_thresholds) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    m_rx_mcs_160_allocated = true;
    return true;
}

uint16_t* cStaHeCapability::rx_mcs_160() {
    if (!m_supported_channel_width_set || !(m_supported_channel_width_set->bw_160_in_5)) {
        TLVF_LOG(ERROR) << "rx_mcs_160 requested but condition not met: m_supported_channel_width_set->bw_160_in_5";
        return nullptr;
    }
    return (uint16_t*)(m_rx_mcs_160);
}

bool cStaHeCapability::set_rx_mcs_160(const uint16_t rx_mcs_160) {
    if (!m_rx_mcs_160_allocated && !alloc_rx_mcs_160()) {
        LOG(ERROR) << "Could not allocate rx_mcs_160!";
        return false;
    }
    *m_rx_mcs_160 = rx_mcs_160;
    return true;
}

bool cStaHeCapability::alloc_tx_mcs_160() {
    if (m_tx_mcs_160_allocated) {
        LOG(ERROR) << "tx_mcs_160 already allocated!";
        return false;
    }
    size_t len = sizeof(uint16_t);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_tx_mcs_160;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_rx_mcs_80_80 = (uint16_t *)((uint8_t *)(m_rx_mcs_80_80) + len);
    m_tx_mcs_80_80 = (uint16_t *)((uint8_t *)(m_tx_mcs_80_80) + len);
    m_ppe_thresholds = (uint8_t *)((uint8_t *)(m_ppe_thresholds) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    m_tx_mcs_160_allocated = true;
    return true;
}

uint16_t* cStaHeCapability::tx_mcs_160() {
    if (!m_supported_channel_width_set || !(m_supported_channel_width_set->bw_160_in_5)) {
        TLVF_LOG(ERROR) << "tx_mcs_160 requested but condition not met: m_supported_channel_width_set->bw_160_in_5";
        return nullptr;
    }
    return (uint16_t*)(m_tx_mcs_160);
}

bool cStaHeCapability::set_tx_mcs_160(const uint16_t tx_mcs_160) {
    if (!m_tx_mcs_160_allocated && !alloc_tx_mcs_160()) {
        LOG(ERROR) << "Could not allocate tx_mcs_160!";
        return false;
    }
    *m_tx_mcs_160 = tx_mcs_160;
    return true;
}

bool cStaHeCapability::alloc_rx_mcs_80_80() {
    if (m_rx_mcs_80_80_allocated) {
        LOG(ERROR) << "rx_mcs_80_80 already allocated!";
        return false;
    }
    size_t len = sizeof(uint16_t);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_rx_mcs_80_80;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_tx_mcs_80_80 = (uint16_t *)((uint8_t *)(m_tx_mcs_80_80) + len);
    m_ppe_thresholds = (uint8_t *)((uint8_t *)(m_ppe_thresholds) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    m_rx_mcs_80_80_allocated = true;
    return true;
}

uint16_t* cStaHeCapability::rx_mcs_80_80() {
    if (!m_supported_channel_width_set || !(m_supported_channel_width_set->bw_160_80p80_in_5)) {
        TLVF_LOG(ERROR) << "rx_mcs_80_80 requested but condition not met: m_supported_channel_width_set->bw_160_80p80_in_5";
        return nullptr;
    }
    return (uint16_t*)(m_rx_mcs_80_80);
}

bool cStaHeCapability::set_rx_mcs_80_80(const uint16_t rx_mcs_80_80) {
    if (!m_rx_mcs_80_80_allocated && !alloc_rx_mcs_80_80()) {
        LOG(ERROR) << "Could not allocate rx_mcs_80_80!";
        return false;
    }
    *m_rx_mcs_80_80 = rx_mcs_80_80;
    return true;
}

bool cStaHeCapability::alloc_tx_mcs_80_80() {
    if (m_tx_mcs_80_80_allocated) {
        LOG(ERROR) << "tx_mcs_80_80 already allocated!";
        return false;
    }
    size_t len = sizeof(uint16_t);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_tx_mcs_80_80;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_ppe_thresholds = (uint8_t *)((uint8_t *)(m_ppe_thresholds) + len);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    m_tx_mcs_80_80_allocated = true;
    return true;
}

uint16_t* cStaHeCapability::tx_mcs_80_80() {
    if (!m_supported_channel_width_set || !(m_supported_channel_width_set->bw_160_80p80_in_5)) {
        TLVF_LOG(ERROR) << "tx_mcs_80_80 requested but condition not met: m_supported_channel_width_set->bw_160_80p80_in_5";
        return nullptr;
    }
    return (uint16_t*)(m_tx_mcs_80_80);
}

bool cStaHeCapability::set_tx_mcs_80_80(const uint16_t tx_mcs_80_80) {
    if (!m_tx_mcs_80_80_allocated && !alloc_tx_mcs_80_80()) {
        LOG(ERROR) << "Could not allocate tx_mcs_80_80!";
        return false;
    }
    *m_tx_mcs_80_80 = tx_mcs_80_80;
    return true;
}

uint8_t* cStaHeCapability::ppe_thresholds(size_t idx) {
    if ( (m_ppe_thresholds_idx__ == 0) || (m_ppe_thresholds_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_ppe_thresholds[idx]);
}

bool cStaHeCapability::set_ppe_thresholds(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_ppe_thresholds received a null pointer.";
        return false;
    }
    if (m_ppe_thresholds_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_ppe_thresholds was already allocated!";
        return false;
    }
    if (!alloc_ppe_thresholds(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_ppe_thresholds);
    return true;
}
bool cStaHeCapability::alloc_ppe_thresholds(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ppe_thresholds, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_ppe_thresholds[m_ppe_thresholds_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_ppe_thresholds_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cStaHeCapability::class_swap()
{
    m_mac_cap_info1->struct_swap();
    m_mac_cap_info2->struct_swap();
    m_supported_channel_width_set->struct_swap();
    m_phy_cap_info1->struct_swap();
    m_phy_cap_info2->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_rx_mcs_le_80));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_tx_mcs_le_80));
    if (m_supported_channel_width_set->bw_160_in_5) {
        tlvf_swap(16, reinterpret_cast<uint8_t*>(m_rx_mcs_160));
    }
    if (m_supported_channel_width_set->bw_160_in_5) {
        tlvf_swap(16, reinterpret_cast<uint8_t*>(m_tx_mcs_160));
    }
    if (m_supported_channel_width_set->bw_160_80p80_in_5) {
        tlvf_swap(16, reinterpret_cast<uint8_t*>(m_rx_mcs_80_80));
    }
    if (m_supported_channel_width_set->bw_160_80p80_in_5) {
        tlvf_swap(16, reinterpret_cast<uint8_t*>(m_tx_mcs_80_80));
    }
}

bool cStaHeCapability::finalize()
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

size_t cStaHeCapability::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eElementID); // type
    class_size += sizeof(uint8_t); // length
    class_size += sizeof(eExtElementID); // subtype
    class_size += sizeof(assoc_frame::sStaHeMacCapInfo1); // mac_cap_info1
    class_size += sizeof(assoc_frame::sStaHeMacCapInfo2); // mac_cap_info2
    class_size += sizeof(sStaHePhyCapInfoB1); // supported_channel_width_set
    class_size += sizeof(assoc_frame::sStaHePhyCapInfo1); // phy_cap_info1
    class_size += sizeof(assoc_frame::sStaHePhyCapInfo2); // phy_cap_info2
    class_size += sizeof(uint16_t); // rx_mcs_le_80
    class_size += sizeof(uint16_t); // tx_mcs_le_80
    return class_size;
}

bool cStaHeCapability::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eElementID*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ID_EID_EXTENSION;
    if (!buffPtrIncrementSafe(sizeof(eElementID))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eElementID) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_subtype = reinterpret_cast<eExtElementID*>(m_buff_ptr__);
    if (!m_parse__) *m_subtype = EXTID_HE_CAPABILITIES;
    if (!buffPtrIncrementSafe(sizeof(eExtElementID))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eExtElementID) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eExtElementID); }
    m_mac_cap_info1 = reinterpret_cast<assoc_frame::sStaHeMacCapInfo1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(assoc_frame::sStaHeMacCapInfo1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(assoc_frame::sStaHeMacCapInfo1) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(assoc_frame::sStaHeMacCapInfo1); }
    if (!m_parse__) { m_mac_cap_info1->struct_init(); }
    m_mac_cap_info2 = reinterpret_cast<assoc_frame::sStaHeMacCapInfo2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(assoc_frame::sStaHeMacCapInfo2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(assoc_frame::sStaHeMacCapInfo2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(assoc_frame::sStaHeMacCapInfo2); }
    if (!m_parse__) { m_mac_cap_info2->struct_init(); }
    m_supported_channel_width_set = reinterpret_cast<sStaHePhyCapInfoB1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sStaHePhyCapInfoB1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sStaHePhyCapInfoB1) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sStaHePhyCapInfoB1); }
    if (!m_parse__) { m_supported_channel_width_set->struct_init(); }
    m_phy_cap_info1 = reinterpret_cast<assoc_frame::sStaHePhyCapInfo1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(assoc_frame::sStaHePhyCapInfo1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(assoc_frame::sStaHePhyCapInfo1) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(assoc_frame::sStaHePhyCapInfo1); }
    if (!m_parse__) { m_phy_cap_info1->struct_init(); }
    m_phy_cap_info2 = reinterpret_cast<assoc_frame::sStaHePhyCapInfo2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(assoc_frame::sStaHePhyCapInfo2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(assoc_frame::sStaHePhyCapInfo2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(assoc_frame::sStaHePhyCapInfo2); }
    if (!m_parse__) { m_phy_cap_info2->struct_init(); }
    m_rx_mcs_le_80 = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_tx_mcs_le_80 = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_rx_mcs_160 = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if ((m_supported_channel_width_set->bw_160_in_5) && !buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_tx_mcs_160 = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if ((m_supported_channel_width_set->bw_160_in_5) && !buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_rx_mcs_80_80 = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if ((m_supported_channel_width_set->bw_160_80p80_in_5) && !buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_tx_mcs_80_80 = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if ((m_supported_channel_width_set->bw_160_80p80_in_5) && !buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_ppe_thresholds = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_ppe_thresholds_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}


