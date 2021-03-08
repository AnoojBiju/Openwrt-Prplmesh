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

#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvProfile2ChannelScanResult::tlvProfile2ChannelScanResult(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvProfile2ChannelScanResult::tlvProfile2ChannelScanResult(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvProfile2ChannelScanResult::~tlvProfile2ChannelScanResult() {
}
const eTlvTypeMap& tlvProfile2ChannelScanResult::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvProfile2ChannelScanResult::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvProfile2ChannelScanResult::radio_uid() {
    return (sMacAddr&)(*m_radio_uid);
}

uint8_t& tlvProfile2ChannelScanResult::operating_class() {
    return (uint8_t&)(*m_operating_class);
}

uint8_t& tlvProfile2ChannelScanResult::channel() {
    return (uint8_t&)(*m_channel);
}

tlvProfile2ChannelScanResult::eScanStatus& tlvProfile2ChannelScanResult::success() {
    return (eScanStatus&)(*m_success);
}

uint8_t& tlvProfile2ChannelScanResult::timestamp_length() {
    return (uint8_t&)(*m_timestamp_length);
}

std::string tlvProfile2ChannelScanResult::timestamp_str() {
    char *timestamp_ = timestamp();
    if (!timestamp_) { return std::string(); }
    return std::string(timestamp_, m_timestamp_idx__);
}

char* tlvProfile2ChannelScanResult::timestamp(size_t length) {
    if( (m_timestamp_idx__ == 0) || (m_timestamp_idx__ < length) ) {
        TLVF_LOG(ERROR) << "timestamp length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_timestamp);
}

bool tlvProfile2ChannelScanResult::set_timestamp(const std::string& str) { return set_timestamp(str.c_str(), str.size()); }
bool tlvProfile2ChannelScanResult::set_timestamp(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_timestamp received a null pointer.";
        return false;
    }
    if (m_timestamp_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_timestamp was already allocated!";
        return false;
    }
    if (!alloc_timestamp(size)) { return false; }
    std::copy(str, str + size, m_timestamp);
    return true;
}
bool tlvProfile2ChannelScanResult::alloc_timestamp(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list timestamp, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_timestamp[*m_timestamp_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_utilization = (uint8_t *)((uint8_t *)(m_utilization) + len);
    m_noise = (uint8_t *)((uint8_t *)(m_noise) + len);
    m_neighbors_list_length = (uint16_t *)((uint8_t *)(m_neighbors_list_length) + len);
    m_neighbors_list = (cNeighbors *)((uint8_t *)(m_neighbors_list) + len);
    m_aggregate_scan_duration = (uint32_t *)((uint8_t *)(m_aggregate_scan_duration) + len);
    m_scan_type = (eScanType *)((uint8_t *)(m_scan_type) + len);
    m_timestamp_idx__ += count;
    *m_timestamp_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

uint8_t& tlvProfile2ChannelScanResult::utilization() {
    return (uint8_t&)(*m_utilization);
}

uint8_t& tlvProfile2ChannelScanResult::noise() {
    return (uint8_t&)(*m_noise);
}

uint16_t& tlvProfile2ChannelScanResult::neighbors_list_length() {
    return (uint16_t&)(*m_neighbors_list_length);
}

std::tuple<bool, cNeighbors&> tlvProfile2ChannelScanResult::neighbors_list(size_t idx) {
    bool ret_success = ( (m_neighbors_list_idx__ > 0) && (m_neighbors_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_neighbors_list_vector[ret_idx]));
}

std::shared_ptr<cNeighbors> tlvProfile2ChannelScanResult::create_neighbors_list() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list neighbors_list, abort!";
        return nullptr;
    }
    size_t len = cNeighbors::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 1;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_neighbors_list;
    if (m_neighbors_list_idx__ > 0) {
        src = (uint8_t *)m_neighbors_list_vector[m_neighbors_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_aggregate_scan_duration = (uint32_t *)((uint8_t *)(m_aggregate_scan_duration) + len);
    m_scan_type = (eScanType *)((uint8_t *)(m_scan_type) + len);
    return std::make_shared<cNeighbors>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvProfile2ChannelScanResult::add_neighbors_list(std::shared_ptr<cNeighbors> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_neighbors_list was called before add_neighbors_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_neighbors_list;
    if (m_neighbors_list_idx__ > 0) {
        src = (uint8_t *)m_neighbors_list_vector[m_neighbors_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_neighbors_list_idx__++;
    if (!m_parse__) { (*m_neighbors_list_length)++; }
    size_t len = ptr->getLen();
    m_aggregate_scan_duration = (uint32_t *)((uint8_t *)(m_aggregate_scan_duration) + len - ptr->get_initial_size());
    m_scan_type = (eScanType *)((uint8_t *)(m_scan_type) + len - ptr->get_initial_size());
    m_neighbors_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

uint32_t& tlvProfile2ChannelScanResult::aggregate_scan_duration() {
    return (uint32_t&)(*m_aggregate_scan_duration);
}

tlvProfile2ChannelScanResult::eScanType& tlvProfile2ChannelScanResult::scan_type() {
    return (eScanType&)(*m_scan_type);
}

void tlvProfile2ChannelScanResult::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_radio_uid->struct_swap();
    tlvf_swap(8*sizeof(eScanStatus), reinterpret_cast<uint8_t*>(m_success));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_neighbors_list_length));
    for (size_t i = 0; i < m_neighbors_list_idx__; i++){
        std::get<1>(neighbors_list(i)).class_swap();
    }
    tlvf_swap(32, reinterpret_cast<uint8_t*>(m_aggregate_scan_duration));
    tlvf_swap(8*sizeof(eScanType), reinterpret_cast<uint8_t*>(m_scan_type));
}

bool tlvProfile2ChannelScanResult::finalize()
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

size_t tlvProfile2ChannelScanResult::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // radio_uid
    class_size += sizeof(uint8_t); // operating_class
    class_size += sizeof(uint8_t); // channel
    class_size += sizeof(eScanStatus); // success
    class_size += sizeof(uint8_t); // timestamp_length
    class_size += sizeof(uint8_t); // utilization
    class_size += sizeof(uint8_t); // noise
    class_size += sizeof(uint16_t); // neighbors_list_length
    class_size += sizeof(uint32_t); // aggregate_scan_duration
    class_size += sizeof(eScanType); // scan_type
    return class_size;
}

bool tlvProfile2ChannelScanResult::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_CHANNEL_SCAN_RESULT;
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
    m_radio_uid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_radio_uid->struct_init(); }
    m_operating_class = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_channel = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_success = reinterpret_cast<eScanStatus*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eScanStatus))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eScanStatus) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eScanStatus); }
    m_timestamp_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_timestamp_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_timestamp = (char*)m_buff_ptr__;
    uint8_t timestamp_length = *m_timestamp_length;
    m_timestamp_idx__ = timestamp_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (timestamp_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (timestamp_length) << ") Failed!";
        return false;
    }
    m_utilization = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_noise = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_neighbors_list_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_neighbors_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_neighbors_list = (cNeighbors*)m_buff_ptr__;
    uint16_t neighbors_list_length = *m_neighbors_list_length;
    if (m_parse__) {  tlvf_swap(16, reinterpret_cast<uint8_t*>(&neighbors_list_length)); }
    m_neighbors_list_idx__ = 0;
    for (size_t i = 0; i < neighbors_list_length; i++) {
        auto neighbors_list = create_neighbors_list();
        if (!neighbors_list) {
            TLVF_LOG(ERROR) << "create_neighbors_list() failed";
            return false;
        }
        if (!add_neighbors_list(neighbors_list)) {
            TLVF_LOG(ERROR) << "add_neighbors_list() failed";
            return false;
        }
        // swap back since neighbors_list will be swapped as part of the whole class swap
        neighbors_list->class_swap();
    }
    m_aggregate_scan_duration = reinterpret_cast<uint32_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint32_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint32_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint32_t); }
    m_scan_type = reinterpret_cast<eScanType*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eScanType))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eScanType) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eScanType); }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_CHANNEL_SCAN_RESULT) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_CHANNEL_SCAN_RESULT) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cNeighbors::cNeighbors(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cNeighbors::cNeighbors(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cNeighbors::~cNeighbors() {
}
sMacAddr& cNeighbors::bssid() {
    return (sMacAddr&)(*m_bssid);
}

uint8_t& cNeighbors::ssid_length() {
    return (uint8_t&)(*m_ssid_length);
}

std::string cNeighbors::ssid_str() {
    char *ssid_ = ssid();
    if (!ssid_) { return std::string(); }
    return std::string(ssid_, m_ssid_idx__);
}

char* cNeighbors::ssid(size_t length) {
    if( (m_ssid_idx__ == 0) || (m_ssid_idx__ < length) ) {
        TLVF_LOG(ERROR) << "ssid length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_ssid);
}

bool cNeighbors::set_ssid(const std::string& str) { return set_ssid(str.c_str(), str.size()); }
bool cNeighbors::set_ssid(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_ssid received a null pointer.";
        return false;
    }
    if (m_ssid_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_ssid was already allocated!";
        return false;
    }
    if (!alloc_ssid(size)) { return false; }
    std::copy(str, str + size, m_ssid);
    return true;
}
bool cNeighbors::alloc_ssid(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list ssid, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_ssid[*m_ssid_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_signal_strength = (uint8_t *)((uint8_t *)(m_signal_strength) + len);
    m_channel_bw_length = (uint8_t *)((uint8_t *)(m_channel_bw_length) + len);
    m_channels_bw_list = (char *)((uint8_t *)(m_channels_bw_list) + len);
    m_bss_load_element_present = (eBssLoadElementPresent *)((uint8_t *)(m_bss_load_element_present) + len);
    m_bss_load_element_length = (uint8_t *)((uint8_t *)(m_bss_load_element_length) + len);
    m_bss_load_element = (sBssLoadElement *)((uint8_t *)(m_bss_load_element) + len);
    m_ssid_idx__ += count;
    *m_ssid_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

uint8_t& cNeighbors::signal_strength() {
    return (uint8_t&)(*m_signal_strength);
}

uint8_t& cNeighbors::channel_bw_length() {
    return (uint8_t&)(*m_channel_bw_length);
}

std::string cNeighbors::channels_bw_list_str() {
    char *channels_bw_list_ = channels_bw_list();
    if (!channels_bw_list_) { return std::string(); }
    return std::string(channels_bw_list_, m_channels_bw_list_idx__);
}

char* cNeighbors::channels_bw_list(size_t length) {
    if( (m_channels_bw_list_idx__ == 0) || (m_channels_bw_list_idx__ < length) ) {
        TLVF_LOG(ERROR) << "channels_bw_list length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_channels_bw_list);
}

bool cNeighbors::set_channels_bw_list(const std::string& str) { return set_channels_bw_list(str.c_str(), str.size()); }
bool cNeighbors::set_channels_bw_list(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_channels_bw_list received a null pointer.";
        return false;
    }
    if (m_channels_bw_list_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_channels_bw_list was already allocated!";
        return false;
    }
    if (!alloc_channels_bw_list(size)) { return false; }
    std::copy(str, str + size, m_channels_bw_list);
    return true;
}
bool cNeighbors::alloc_channels_bw_list(size_t count) {
    if (m_lock_order_counter__ > 1) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list channels_bw_list, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 1;
    uint8_t *src = (uint8_t *)&m_channels_bw_list[*m_channel_bw_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_bss_load_element_present = (eBssLoadElementPresent *)((uint8_t *)(m_bss_load_element_present) + len);
    m_bss_load_element_length = (uint8_t *)((uint8_t *)(m_bss_load_element_length) + len);
    m_bss_load_element = (sBssLoadElement *)((uint8_t *)(m_bss_load_element) + len);
    m_channels_bw_list_idx__ += count;
    *m_channel_bw_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

cNeighbors::eBssLoadElementPresent& cNeighbors::bss_load_element_present() {
    return (eBssLoadElementPresent&)(*m_bss_load_element_present);
}

uint8_t& cNeighbors::bss_load_element_length() {
    return (uint8_t&)(*m_bss_load_element_length);
}

std::tuple<bool, cNeighbors::sBssLoadElement&> cNeighbors::bss_load_element(size_t idx) {
    bool ret_success = ( (m_bss_load_element_idx__ > 0) && (m_bss_load_element_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_bss_load_element[ret_idx]);
}

bool cNeighbors::alloc_bss_load_element(size_t count) {
    if (m_lock_order_counter__ > 2) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bss_load_element, abort!";
        return false;
    }
    size_t len = sizeof(sBssLoadElement) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    if (m_bss_load_element_idx__ + count > 1 )  {
        TLVF_LOG(ERROR) << "Can't allocate " << count << " elements (max length is " << 1 << " current length is " << m_bss_load_element_idx__ << ")";
        return false;
    }
    m_lock_order_counter__ = 2;
    uint8_t *src = (uint8_t *)&m_bss_load_element[*m_bss_load_element_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_bss_load_element_idx__ += count;
    *m_bss_load_element_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if (!m_parse__) { 
        for (size_t i = m_bss_load_element_idx__ - count; i < m_bss_load_element_idx__; i++) { m_bss_load_element[i].struct_init(); }
    }
    return true;
}

void cNeighbors::class_swap()
{
    m_bssid->struct_swap();
    tlvf_swap(8*sizeof(eBssLoadElementPresent), reinterpret_cast<uint8_t*>(m_bss_load_element_present));
    for (size_t i = 0; i < m_bss_load_element_idx__; i++){
        m_bss_load_element[i].struct_swap();
    }
}

bool cNeighbors::finalize()
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
    }
    class_swap();
    m_finalized__ = true;
    return true;
}

size_t cNeighbors::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(uint8_t); // ssid_length
    class_size += sizeof(uint8_t); // signal_strength
    class_size += sizeof(uint8_t); // channel_bw_length
    class_size += sizeof(eBssLoadElementPresent); // bss_load_element_present
    class_size += sizeof(uint8_t); // bss_load_element_length
    return class_size;
}

bool cNeighbors::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_ssid_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_ssid_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_ssid = (char*)m_buff_ptr__;
    uint8_t ssid_length = *m_ssid_length;
    m_ssid_idx__ = ssid_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (ssid_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (ssid_length) << ") Failed!";
        return false;
    }
    m_signal_strength = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_channel_bw_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_channel_bw_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_channels_bw_list = (char*)m_buff_ptr__;
    uint8_t channel_bw_length = *m_channel_bw_length;
    m_channels_bw_list_idx__ = channel_bw_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (channel_bw_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (channel_bw_length) << ") Failed!";
        return false;
    }
    m_bss_load_element_present = reinterpret_cast<eBssLoadElementPresent*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(eBssLoadElementPresent))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eBssLoadElementPresent) << ") Failed!";
        return false;
    }
    m_bss_load_element_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_bss_load_element_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bss_load_element = (sBssLoadElement*)m_buff_ptr__;
    uint8_t bss_load_element_length = *m_bss_load_element_length;
    m_bss_load_element_idx__ = bss_load_element_length;
    if (!buffPtrIncrementSafe(sizeof(sBssLoadElement) * (bss_load_element_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sBssLoadElement) * (bss_load_element_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


