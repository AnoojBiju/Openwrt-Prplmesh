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

#include <tlvf/ieee_1905_1/tlv1905NeighborDevice.h>
#include <tlvf/tlvflogging.h>

using namespace ieee1905_1;

tlv1905NeighborDevice::tlv1905NeighborDevice(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlv1905NeighborDevice::tlv1905NeighborDevice(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlv1905NeighborDevice::~tlv1905NeighborDevice() {
}
const eTlvType& tlv1905NeighborDevice::type() {
    return (const eTlvType&)(*m_type);
}

const uint16_t& tlv1905NeighborDevice::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlv1905NeighborDevice::mac_local_iface() {
    return (sMacAddr&)(*m_mac_local_iface);
}

std::tuple<bool, tlv1905NeighborDevice::sMacAl1905Device&> tlv1905NeighborDevice::mac_al_1905_device(size_t idx) {
    bool ret_success = ( (m_mac_al_1905_device_idx__ > 0) && (m_mac_al_1905_device_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_mac_al_1905_device[ret_idx]);
}

bool tlv1905NeighborDevice::alloc_mac_al_1905_device(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list mac_al_1905_device, abort!";
        return false;
    }
    size_t len = sizeof(sMacAl1905Device) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_mac_al_1905_device[m_mac_al_1905_device_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_mac_al_1905_device_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    if (!m_parse__) { 
        for (size_t i = m_mac_al_1905_device_idx__ - count; i < m_mac_al_1905_device_idx__; i++) { m_mac_al_1905_device[i].struct_init(); }
    }
    return true;
}

void tlv1905NeighborDevice::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_mac_local_iface->struct_swap();
    for (size_t i = 0; i < m_mac_al_1905_device_idx__; i++){
        m_mac_al_1905_device[i].struct_swap();
    }
}

bool tlv1905NeighborDevice::finalize()
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

size_t tlv1905NeighborDevice::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvType); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // mac_local_iface
    return class_size;
}

bool tlv1905NeighborDevice::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvType*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvType::TLV_1905_NEIGHBOR_DEVICE;
    if (!buffPtrIncrementSafe(sizeof(eTlvType))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eTlvType) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_mac_local_iface = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_mac_local_iface->struct_init(); }
    m_mac_al_1905_device = reinterpret_cast<sMacAl1905Device*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_mac_al_1905_device_idx__ = len/sizeof(sMacAl1905Device);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvType::TLV_1905_NEIGHBOR_DEVICE) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvType::TLV_1905_NEIGHBOR_DEVICE) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


