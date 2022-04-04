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

#include <tlvf/wfa_map/tlv1905LayerSecurityCapability.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlv1905LayerSecurityCapability::tlv1905LayerSecurityCapability(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlv1905LayerSecurityCapability::tlv1905LayerSecurityCapability(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlv1905LayerSecurityCapability::~tlv1905LayerSecurityCapability() {
}
const eTlvTypeMap& tlv1905LayerSecurityCapability::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlv1905LayerSecurityCapability::length() {
    return (const uint16_t&)(*m_length);
}

tlv1905LayerSecurityCapability::eOnboardingProtocol& tlv1905LayerSecurityCapability::onboarding_protocol() {
    return (eOnboardingProtocol&)(*m_onboarding_protocol);
}

tlv1905LayerSecurityCapability::eMicAlgorithm& tlv1905LayerSecurityCapability::mic_algorithm() {
    return (eMicAlgorithm&)(*m_mic_algorithm);
}

tlv1905LayerSecurityCapability::eEncryptionAlgorithm& tlv1905LayerSecurityCapability::encryption_algorithm() {
    return (eEncryptionAlgorithm&)(*m_encryption_algorithm);
}

void tlv1905LayerSecurityCapability::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    tlvf_swap(8*sizeof(eOnboardingProtocol), reinterpret_cast<uint8_t*>(m_onboarding_protocol));
    tlvf_swap(8*sizeof(eMicAlgorithm), reinterpret_cast<uint8_t*>(m_mic_algorithm));
    tlvf_swap(8*sizeof(eEncryptionAlgorithm), reinterpret_cast<uint8_t*>(m_encryption_algorithm));
}

bool tlv1905LayerSecurityCapability::finalize()
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

size_t tlv1905LayerSecurityCapability::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(eOnboardingProtocol); // onboarding_protocol
    class_size += sizeof(eMicAlgorithm); // mic_algorithm
    class_size += sizeof(eEncryptionAlgorithm); // encryption_algorithm
    return class_size;
}

bool tlv1905LayerSecurityCapability::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_1905_LAYER_SECURITY_CAPABILITY;
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
    m_onboarding_protocol = reinterpret_cast<eOnboardingProtocol*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eOnboardingProtocol))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eOnboardingProtocol) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eOnboardingProtocol); }
    m_mic_algorithm = reinterpret_cast<eMicAlgorithm*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eMicAlgorithm))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eMicAlgorithm) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eMicAlgorithm); }
    m_encryption_algorithm = reinterpret_cast<eEncryptionAlgorithm*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eEncryptionAlgorithm))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eEncryptionAlgorithm) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eEncryptionAlgorithm); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_1905_LAYER_SECURITY_CAPABILITY) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_1905_LAYER_SECURITY_CAPABILITY) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


