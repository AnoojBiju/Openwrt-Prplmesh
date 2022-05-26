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

#include <tlvf/wfa_map/tlvMic.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvMic::tlvMic(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvMic::tlvMic(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvMic::~tlvMic() {
}
const eTlvTypeMap& tlvMic::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvMic::length() {
    return (const uint16_t&)(*m_length);
}

tlvMic::sFlags& tlvMic::flags() {
    return (sFlags&)(*m_flags);
}

uint8_t* tlvMic::integrity_transmission_counter(size_t idx) {
    if ( (m_integrity_transmission_counter_idx__ == 0) || (m_integrity_transmission_counter_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_integrity_transmission_counter[idx]);
}

bool tlvMic::set_integrity_transmission_counter(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_integrity_transmission_counter received a null pointer.";
        return false;
    }
    if (size > 6) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than buffer length";
        return false;
    }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_integrity_transmission_counter);
    return true;
}
sMacAddr& tlvMic::source_1905_al_mac_address() {
    return (sMacAddr&)(*m_source_1905_al_mac_address);
}

uint16_t& tlvMic::mic_length() {
    return (uint16_t&)(*m_mic_length);
}

uint8_t* tlvMic::mic(size_t idx) {
    if ( (m_mic_idx__ == 0) || (m_mic_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_mic[idx]);
}

bool tlvMic::set_mic(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_mic received a null pointer.";
        return false;
    }
    if (m_mic_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_mic was already allocated!";
        return false;
    }
    if (!alloc_mic(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_mic);
    return true;
}
bool tlvMic::alloc_mic(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list mic, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_mic[*m_mic_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_mic_idx__ += count;
    *m_mic_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void tlvMic::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_flags->struct_swap();
    m_source_1905_al_mac_address->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_mic_length));
}

bool tlvMic::finalize()
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

size_t tlvMic::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sFlags); // flags
    class_size += 6 * sizeof(uint8_t); // integrity_transmission_counter
    class_size += sizeof(sMacAddr); // source_1905_al_mac_address
    class_size += sizeof(uint16_t); // mic_length
    return class_size;
}

bool tlvMic::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_MIC;
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
    m_flags = reinterpret_cast<sFlags*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFlags))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFlags) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sFlags); }
    if (!m_parse__) { m_flags->struct_init(); }
    m_integrity_transmission_counter = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (6))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (6) << ") Failed!";
        return false;
    }
    m_integrity_transmission_counter_idx__  = 6;
    if (!m_parse__) {
        if (m_length) { (*m_length) += (sizeof(uint8_t) * 6); }
    }
    m_source_1905_al_mac_address = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_source_1905_al_mac_address->struct_init(); }
    m_mic_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_mic_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_mic = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    uint16_t mic_length = *m_mic_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&mic_length)); }
    m_mic_idx__ = mic_length;
    if (!buffPtrIncrementSafe(sizeof(uint8_t) * (mic_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) * (mic_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_MIC) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_MIC) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


