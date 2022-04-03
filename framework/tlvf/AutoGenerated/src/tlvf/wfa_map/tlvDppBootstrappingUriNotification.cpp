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

#include <tlvf/wfa_map/tlvDppBootstrappingUriNotification.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvDppBootstrappingUriNotification::tlvDppBootstrappingUriNotification(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvDppBootstrappingUriNotification::tlvDppBootstrappingUriNotification(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvDppBootstrappingUriNotification::~tlvDppBootstrappingUriNotification() {
}
const eTlvTypeMap& tlvDppBootstrappingUriNotification::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvDppBootstrappingUriNotification::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvDppBootstrappingUriNotification::ruid() {
    return (sMacAddr&)(*m_ruid);
}

sMacAddr& tlvDppBootstrappingUriNotification::bssid() {
    return (sMacAddr&)(*m_bssid);
}

sMacAddr& tlvDppBootstrappingUriNotification::backhaul_sta_address() {
    return (sMacAddr&)(*m_backhaul_sta_address);
}

std::string tlvDppBootstrappingUriNotification::dpp_uri_str() {
    char *dpp_uri_ = dpp_uri();
    if (!dpp_uri_) { return std::string(); }
    auto str = std::string(dpp_uri_, m_dpp_uri_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* tlvDppBootstrappingUriNotification::dpp_uri(size_t length) {
    if( (m_dpp_uri_idx__ == 0) || (m_dpp_uri_idx__ < length) ) {
        TLVF_LOG(ERROR) << "dpp_uri length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_dpp_uri);
}

bool tlvDppBootstrappingUriNotification::set_dpp_uri(const std::string& str) { return set_dpp_uri(str.c_str(), str.size()); }
bool tlvDppBootstrappingUriNotification::set_dpp_uri(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_dpp_uri received a null pointer.";
        return false;
    }
    if (m_dpp_uri_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_dpp_uri was already allocated!";
        return false;
    }
    if (!alloc_dpp_uri(size)) { return false; }
    std::copy(str, str + size, m_dpp_uri);
    return true;
}
bool tlvDppBootstrappingUriNotification::alloc_dpp_uri(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list dpp_uri, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_dpp_uri[m_dpp_uri_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_dpp_uri_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void tlvDppBootstrappingUriNotification::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_ruid->struct_swap();
    m_bssid->struct_swap();
    m_backhaul_sta_address->struct_swap();
}

bool tlvDppBootstrappingUriNotification::finalize()
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

size_t tlvDppBootstrappingUriNotification::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(sMacAddr); // backhaul_sta_address
    return class_size;
}

bool tlvDppBootstrappingUriNotification::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_DPP_BOOTSTRAPPING_URI_NOTIFICATION;
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
    m_ruid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_ruid->struct_init(); }
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_backhaul_sta_address = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_backhaul_sta_address->struct_init(); }
    m_dpp_uri = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_dpp_uri_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_DPP_BOOTSTRAPPING_URI_NOTIFICATION) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_DPP_BOOTSTRAPPING_URI_NOTIFICATION) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


