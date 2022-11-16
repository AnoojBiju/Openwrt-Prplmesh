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

#include <tlvf/wfa_map/tlvQoSManagementDescriptor.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvQoSManagementDescriptor::tlvQoSManagementDescriptor(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvQoSManagementDescriptor::tlvQoSManagementDescriptor(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvQoSManagementDescriptor::~tlvQoSManagementDescriptor() {
}
const eTlvTypeMap& tlvQoSManagementDescriptor::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvQoSManagementDescriptor::length() {
    return (const uint16_t&)(*m_length);
}

uint16_t& tlvQoSManagementDescriptor::qmid() {
    return (uint16_t&)(*m_qmid);
}

sMacAddr& tlvQoSManagementDescriptor::bssid() {
    return (sMacAddr&)(*m_bssid);
}

sMacAddr& tlvQoSManagementDescriptor::client_mac() {
    return (sMacAddr&)(*m_client_mac);
}

uint8_t* tlvQoSManagementDescriptor::descriptor_element(size_t idx) {
    if ( (m_descriptor_element_idx__ == 0) || (m_descriptor_element_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_descriptor_element[idx]);
}

bool tlvQoSManagementDescriptor::set_descriptor_element(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_descriptor_element received a null pointer.";
        return false;
    }
    if (m_descriptor_element_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_descriptor_element was already allocated!";
        return false;
    }
    if (!alloc_descriptor_element(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_descriptor_element);
    return true;
}
bool tlvQoSManagementDescriptor::alloc_descriptor_element(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list descriptor_element, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_descriptor_element[m_descriptor_element_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_descriptor_element_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void tlvQoSManagementDescriptor::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_qmid));
    m_bssid->struct_swap();
    m_client_mac->struct_swap();
}

bool tlvQoSManagementDescriptor::finalize()
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

size_t tlvQoSManagementDescriptor::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint16_t); // qmid
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(sMacAddr); // client_mac
    return class_size;
}

bool tlvQoSManagementDescriptor::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_QOS_MANAGEMENT_DESCRIPTOR;
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
    m_qmid = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_client_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_client_mac->struct_init(); }
    m_descriptor_element = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_descriptor_element_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_QOS_MANAGEMENT_DESCRIPTOR) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_QOS_MANAGEMENT_DESCRIPTOR) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


