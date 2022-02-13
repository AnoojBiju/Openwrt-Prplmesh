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

#include <tlvf/wfa_map/tlvServicePrioritizationRule.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvServicePrioritizationRule::tlvServicePrioritizationRule(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvServicePrioritizationRule::tlvServicePrioritizationRule(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvServicePrioritizationRule::~tlvServicePrioritizationRule() {
}
const eTlvTypeMap& tlvServicePrioritizationRule::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvServicePrioritizationRule::length() {
    return (const uint16_t&)(*m_length);
}

uint32_t& tlvServicePrioritizationRule::rule_id() {
    return (uint32_t&)(*m_rule_id);
}

tlvServicePrioritizationRule::sRuleBitsField1& tlvServicePrioritizationRule::rule_bits_field1() {
    return (sRuleBitsField1&)(*m_rule_bits_field1);
}

uint8_t& tlvServicePrioritizationRule::precedence() {
    return (uint8_t&)(*m_precedence);
}

uint8_t& tlvServicePrioritizationRule::output() {
    return (uint8_t&)(*m_output);
}

tlvServicePrioritizationRule::sRuleBitsField2& tlvServicePrioritizationRule::rule_bits_field2() {
    return (sRuleBitsField2&)(*m_rule_bits_field2);
}

void tlvServicePrioritizationRule::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_rule_id));
    m_rule_bits_field1->struct_swap();
    m_rule_bits_field2->struct_swap();
}

bool tlvServicePrioritizationRule::finalize()
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

size_t tlvServicePrioritizationRule::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint32_t); // rule_id
    class_size += sizeof(sRuleBitsField1); // rule_bits_field1
    class_size += sizeof(uint8_t); // precedence
    class_size += sizeof(uint8_t); // output
    class_size += sizeof(sRuleBitsField2); // rule_bits_field2
    return class_size;
}

bool tlvServicePrioritizationRule::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_SERVICE_PRIORITIZATION_RULE;
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
    m_rule_id = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_rule_bits_field1 = reinterpret_cast<sRuleBitsField1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sRuleBitsField1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sRuleBitsField1) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sRuleBitsField1); }
    if (!m_parse__) { m_rule_bits_field1->struct_init(); }
    m_precedence = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_output = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_rule_bits_field2 = reinterpret_cast<sRuleBitsField2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sRuleBitsField2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sRuleBitsField2) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sRuleBitsField2); }
    if (!m_parse__) { m_rule_bits_field2->struct_init(); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_SERVICE_PRIORITIZATION_RULE) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_SERVICE_PRIORITIZATION_RULE) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


