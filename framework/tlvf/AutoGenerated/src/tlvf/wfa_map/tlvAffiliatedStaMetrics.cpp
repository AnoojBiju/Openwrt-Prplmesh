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

#include <tlvf/wfa_map/tlvAffiliatedStaMetrics.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvAffiliatedStaMetrics::tlvAffiliatedStaMetrics(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvAffiliatedStaMetrics::tlvAffiliatedStaMetrics(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvAffiliatedStaMetrics::~tlvAffiliatedStaMetrics() {
}
const eTlvTypeMap& tlvAffiliatedStaMetrics::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvAffiliatedStaMetrics::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvAffiliatedStaMetrics::sta_mac_addr() {
    return (sMacAddr&)(*m_sta_mac_addr);
}

uint32_t& tlvAffiliatedStaMetrics::bytes_sent() {
    return (uint32_t&)(*m_bytes_sent);
}

uint32_t& tlvAffiliatedStaMetrics::bytes_received() {
    return (uint32_t&)(*m_bytes_received);
}

uint32_t& tlvAffiliatedStaMetrics::packets_sent() {
    return (uint32_t&)(*m_packets_sent);
}

uint32_t& tlvAffiliatedStaMetrics::packets_received() {
    return (uint32_t&)(*m_packets_received);
}

uint32_t& tlvAffiliatedStaMetrics::packets_sent_errors() {
    return (uint32_t&)(*m_packets_sent_errors);
}

uint8_t& tlvAffiliatedStaMetrics::reserved() {
    return (uint8_t&)(*m_reserved);
}

void tlvAffiliatedStaMetrics::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_sta_mac_addr->struct_swap();
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_bytes_sent));
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_bytes_received));
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_packets_sent));
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_packets_received));
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_packets_sent_errors));
}

bool tlvAffiliatedStaMetrics::finalize()
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

size_t tlvAffiliatedStaMetrics::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // sta_mac_addr
    class_size += sizeof(uint32_t); // bytes_sent
    class_size += sizeof(uint32_t); // bytes_received
    class_size += sizeof(uint32_t); // packets_sent
    class_size += sizeof(uint32_t); // packets_received
    class_size += sizeof(uint32_t); // packets_sent_errors
    class_size += sizeof(uint8_t); // reserved
    return class_size;
}

bool tlvAffiliatedStaMetrics::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_AFFILIATED_STA_METRICS;
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
    m_sta_mac_addr = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_sta_mac_addr->struct_init(); }
    m_bytes_sent = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_bytes_received = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_packets_sent = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_packets_received = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_packets_sent_errors = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_reserved = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_AFFILIATED_STA_METRICS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_AFFILIATED_STA_METRICS) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


