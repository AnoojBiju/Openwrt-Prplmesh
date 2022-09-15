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

#include <tlvf/wfa_map/tlvSteeringBTMReport.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvSteeringBTMReport::tlvSteeringBTMReport(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvSteeringBTMReport::tlvSteeringBTMReport(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvSteeringBTMReport::~tlvSteeringBTMReport() {
}
const eTlvTypeMap& tlvSteeringBTMReport::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvSteeringBTMReport::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvSteeringBTMReport::bssid() {
    return (sMacAddr&)(*m_bssid);
}

sMacAddr& tlvSteeringBTMReport::sta_mac() {
    return (sMacAddr&)(*m_sta_mac);
}

tlvSteeringBTMReport::eBTMStatusCode& tlvSteeringBTMReport::btm_status_code() {
    return (eBTMStatusCode&)(*m_btm_status_code);
}

bool tlvSteeringBTMReport::alloc_target_bssid() {
    if (m_target_bssid_allocated) {
        LOG(ERROR) << "target_bssid already allocated!";
        return false;
    }
    size_t len = sizeof(sMacAddr);
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    uint8_t *src = (uint8_t *)m_target_bssid;
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    m_target_bssid_allocated = true;
    return true;
}

sMacAddr* tlvSteeringBTMReport::target_bssid() {
    if (!m_btm_status_code || !(*m_btm_status_code == eBTMStatusCode::ACCEPT)) {
        TLVF_LOG(ERROR) << "target_bssid requested but condition not met: *m_btm_status_code == eBTMStatusCode::ACCEPT";
        return nullptr;
    }
    return (sMacAddr*)(m_target_bssid);
}

bool tlvSteeringBTMReport::set_target_bssid(const sMacAddr target_bssid) {
    if (!m_target_bssid_allocated && !alloc_target_bssid()) {
        LOG(ERROR) << "Could not allocate target_bssid!";
        return false;
    }
    *m_target_bssid = target_bssid;
    return true;
}

void tlvSteeringBTMReport::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_bssid->struct_swap();
    m_sta_mac->struct_swap();
    tlvf_swap(8*sizeof(eBTMStatusCode), reinterpret_cast<uint8_t*>(m_btm_status_code));
    if (*m_btm_status_code == eBTMStatusCode::ACCEPT) {
        m_target_bssid->struct_swap();
    }
}

bool tlvSteeringBTMReport::finalize()
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

size_t tlvSteeringBTMReport::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(sMacAddr); // sta_mac
    class_size += sizeof(eBTMStatusCode); // btm_status_code
    return class_size;
}

bool tlvSteeringBTMReport::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_STEERING_BTM_REPORT;
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
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_sta_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_sta_mac->struct_init(); }
    m_btm_status_code = reinterpret_cast<eBTMStatusCode*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eBTMStatusCode))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eBTMStatusCode) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eBTMStatusCode); }
    m_target_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if ((*m_btm_status_code == eBTMStatusCode::ACCEPT) && !buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_target_bssid->struct_init(); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_STEERING_BTM_REPORT) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_STEERING_BTM_REPORT) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


