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

#include "tlvAPRadioVBSSCapabilities.h"
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvAPRadioVBSSCapabilities::tlvAPRadioVBSSCapabilities(uint8_t *buff, size_t buff_len, bool parse)
    : BaseClass(buff, buff_len, parse)
{
    m_init_succeeded = init();
}
tlvAPRadioVBSSCapabilities::tlvAPRadioVBSSCapabilities(std::shared_ptr<BaseClass> base, bool parse)
    : BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse)
{
    m_init_succeeded = init();
}
tlvAPRadioVBSSCapabilities::~tlvAPRadioVBSSCapabilities() {}
const eTlvTypeMap &tlvAPRadioVBSSCapabilities::type() { return (const eTlvTypeMap &)(*m_type); }

const uint16_t &tlvAPRadioVBSSCapabilities::length() { return (const uint16_t &)(*m_length); }

const uint16_t &tlvAPRadioVBSSCapabilities::subtype() { return (const uint16_t &)(*m_subtype); }

sMacAddr &tlvAPRadioVBSSCapabilities::radio_uid() { return (sMacAddr &)(*m_radio_uid); }

uint8_t &tlvAPRadioVBSSCapabilities::max_vbss() { return (uint8_t &)(*m_max_vbss); }

tlvAPRadioVBSSCapabilities::sVbssSettings &tlvAPRadioVBSSCapabilities::vbss_settings()
{
    return (tlvAPRadioVBSSCapabilities::sVbssSettings &)(*m_vbss_settings);
}

sMacAddr &tlvAPRadioVBSSCapabilities::fixed_bits_mask() { return (sMacAddr &)(*m_fixed_bits_mask); }

sMacAddr &tlvAPRadioVBSSCapabilities::fixed_bits_value()
{
    return (sMacAddr &)(*m_fixed_bits_value);
}

void tlvAPRadioVBSSCapabilities::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t *>(m_length));
    tlvf_swap(16, reinterpret_cast<uint8_t *>(m_subtype));
    m_radio_uid->struct_swap();
    m_vbss_settings->struct_swap();
    m_fixed_bits_mask->struct_swap();
    m_fixed_bits_value->struct_swap();
}

bool tlvAPRadioVBSSCapabilities::finalize()
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

size_t tlvAPRadioVBSSCapabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap);                               // type
    class_size += sizeof(uint16_t);                                  // length
    class_size += sizeof(uint16_t);                                  // subtype
    class_size += sizeof(sMacAddr);                                  // radio_uid
    class_size += sizeof(uint8_t);                                   // max_vbss
    class_size += sizeof(tlvAPRadioVBSSCapabilities::sVbssSettings); // vbss_settings
    class_size += sizeof(sMacAddr);                                  // fixed_bits_mask
    class_size += sizeof(sMacAddr);                                  // fixed_bits_value
    return class_size;
}

bool tlvAPRadioVBSSCapabilities::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap *>(m_buff_ptr__);
    if (!m_parse__)
        *((uint8_t *)m_type) = 0xDE;
    if (!buffPtrIncrementSafe(sizeof(eTlvTypeMap))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eTlvTypeMap) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_subtype = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_subtype = 0x0001;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(uint16_t);
    }
    m_radio_uid = reinterpret_cast<sMacAddr *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(sMacAddr);
    }
    if (!m_parse__) {
        m_radio_uid->struct_init();
    }
    m_max_vbss = reinterpret_cast<uint8_t *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(uint8_t);
    }
    m_vbss_settings = reinterpret_cast<tlvAPRadioVBSSCapabilities::sVbssSettings *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(tlvAPRadioVBSSCapabilities::sVbssSettings))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec
                   << sizeof(tlvAPRadioVBSSCapabilities::sVbssSettings) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(tlvAPRadioVBSSCapabilities::sVbssSettings);
    }
    if (!m_parse__) {
        m_vbss_settings->struct_init();
    }
    m_fixed_bits_mask = reinterpret_cast<sMacAddr *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(sMacAddr);
    }
    if (!m_parse__) {
        m_fixed_bits_mask->struct_init();
    }
    m_fixed_bits_value = reinterpret_cast<sMacAddr *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(sMacAddr);
    }
    if (!m_parse__) {
        m_fixed_bits_value->struct_init();
    }
    if (m_parse__) {
        class_swap();
    }
    if (m_parse__) {
        if (*((uint8_t *)m_type) != 0xDE) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(0xDE)
                            << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}
