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

#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <tlvf/tlvflogging.h>

using namespace beerocks_message;

tlvVsClientAssociationEvent::tlvVsClientAssociationEvent(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvVsClientAssociationEvent::tlvVsClientAssociationEvent(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvVsClientAssociationEvent::~tlvVsClientAssociationEvent() {
}
sMacAddr& tlvVsClientAssociationEvent::mac() {
    return (sMacAddr&)(*m_mac);
}

sMacAddr& tlvVsClientAssociationEvent::bssid() {
    return (sMacAddr&)(*m_bssid);
}

int8_t& tlvVsClientAssociationEvent::vap_id() {
    return (int8_t&)(*m_vap_id);
}

beerocks::message::sRadioCapabilities& tlvVsClientAssociationEvent::capabilities() {
    return (beerocks::message::sRadioCapabilities&)(*m_capabilities);
}

uint8_t& tlvVsClientAssociationEvent::disconnect_reason() {
    return (uint8_t&)(*m_disconnect_reason);
}

uint8_t& tlvVsClientAssociationEvent::disconnect_source() {
    return (uint8_t&)(*m_disconnect_source);
}

uint8_t& tlvVsClientAssociationEvent::disconnect_type() {
    return (uint8_t&)(*m_disconnect_type);
}

void tlvVsClientAssociationEvent::class_swap()
{
    tlvf_swap(8*sizeof(eActionOp_1905_VS), reinterpret_cast<uint8_t*>(m_action_op));
    m_mac->struct_swap();
    m_bssid->struct_swap();
    m_capabilities->struct_swap();
}

bool tlvVsClientAssociationEvent::finalize()
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

size_t tlvVsClientAssociationEvent::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // mac
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(int8_t); // vap_id
    class_size += sizeof(beerocks::message::sRadioCapabilities); // capabilities
    class_size += sizeof(uint8_t); // disconnect_reason
    class_size += sizeof(uint8_t); // disconnect_source
    class_size += sizeof(uint8_t); // disconnect_type
    return class_size;
}

bool tlvVsClientAssociationEvent::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_mac->struct_init(); }
    m_bssid = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_vap_id = reinterpret_cast<int8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(int8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(int8_t) << ") Failed!";
        return false;
    }
    m_capabilities = reinterpret_cast<beerocks::message::sRadioCapabilities*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(beerocks::message::sRadioCapabilities))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(beerocks::message::sRadioCapabilities) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_capabilities->struct_init(); }
    m_disconnect_reason = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_disconnect_source = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_disconnect_type = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}

tlvVsChannelScanRequestExtension::tlvVsChannelScanRequestExtension(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvVsChannelScanRequestExtension::tlvVsChannelScanRequestExtension(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvVsChannelScanRequestExtension::~tlvVsChannelScanRequestExtension() {
}
uint8_t& tlvVsChannelScanRequestExtension::scan_requests_list_length() {
    return (uint8_t&)(*m_scan_requests_list_length);
}

std::tuple<bool, sScanRequestExtension&> tlvVsChannelScanRequestExtension::scan_requests_list(size_t idx) {
    bool ret_success = ( (m_scan_requests_list_idx__ > 0) && (m_scan_requests_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_scan_requests_list[ret_idx]);
}

bool tlvVsChannelScanRequestExtension::alloc_scan_requests_list(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list scan_requests_list, abort!";
        return false;
    }
    size_t len = sizeof(sScanRequestExtension) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_scan_requests_list[*m_scan_requests_list_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_scan_requests_list_idx__ += count;
    *m_scan_requests_list_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if (!m_parse__) { 
        for (size_t i = m_scan_requests_list_idx__ - count; i < m_scan_requests_list_idx__; i++) { m_scan_requests_list[i].struct_init(); }
    }
    return true;
}

void tlvVsChannelScanRequestExtension::class_swap()
{
    tlvf_swap(8*sizeof(eActionOp_1905_VS), reinterpret_cast<uint8_t*>(m_action_op));
    for (size_t i = 0; i < m_scan_requests_list_idx__; i++){
        m_scan_requests_list[i].struct_swap();
    }
}

bool tlvVsChannelScanRequestExtension::finalize()
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

size_t tlvVsChannelScanRequestExtension::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // scan_requests_list_length
    return class_size;
}

bool tlvVsChannelScanRequestExtension::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_scan_requests_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_scan_requests_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_scan_requests_list = reinterpret_cast<sScanRequestExtension*>(m_buff_ptr__);
    uint8_t scan_requests_list_length = *m_scan_requests_list_length;
    m_scan_requests_list_idx__ = scan_requests_list_length;
    if (!buffPtrIncrementSafe(sizeof(sScanRequestExtension) * (scan_requests_list_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sScanRequestExtension) * (scan_requests_list_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}

tlvVsChannelScanReportDone::tlvVsChannelScanReportDone(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvVsChannelScanReportDone::tlvVsChannelScanReportDone(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvVsChannelScanReportDone::~tlvVsChannelScanReportDone() {
}
uint8_t& tlvVsChannelScanReportDone::report_done() {
    return (uint8_t&)(*m_report_done);
}

void tlvVsChannelScanReportDone::class_swap()
{
    tlvf_swap(8*sizeof(eActionOp_1905_VS), reinterpret_cast<uint8_t*>(m_action_op));
}

bool tlvVsChannelScanReportDone::finalize()
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

size_t tlvVsChannelScanReportDone::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // report_done
    return class_size;
}

bool tlvVsChannelScanReportDone::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_report_done = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}

tlvVsOnDemandChannelSelection::tlvVsOnDemandChannelSelection(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvVsOnDemandChannelSelection::tlvVsOnDemandChannelSelection(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvVsOnDemandChannelSelection::~tlvVsOnDemandChannelSelection() {
}
sMacAddr& tlvVsOnDemandChannelSelection::radio_mac() {
    return (sMacAddr&)(*m_radio_mac);
}

uint8_t& tlvVsOnDemandChannelSelection::CSA_count() {
    return (uint8_t&)(*m_CSA_count);
}

void tlvVsOnDemandChannelSelection::class_swap()
{
    tlvf_swap(8*sizeof(eActionOp_1905_VS), reinterpret_cast<uint8_t*>(m_action_op));
    m_radio_mac->struct_swap();
}

bool tlvVsOnDemandChannelSelection::finalize()
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

size_t tlvVsOnDemandChannelSelection::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // radio_mac
    class_size += sizeof(uint8_t); // CSA_count
    return class_size;
}

bool tlvVsOnDemandChannelSelection::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_radio_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_radio_mac->struct_init(); }
    m_CSA_count = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}

tlvVsBssidIfaceMapping::tlvVsBssidIfaceMapping(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvVsBssidIfaceMapping::tlvVsBssidIfaceMapping(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvVsBssidIfaceMapping::~tlvVsBssidIfaceMapping() {
}
uint8_t& tlvVsBssidIfaceMapping::bssid_vap_id_map_length() {
    return (uint8_t&)(*m_bssid_vap_id_map_length);
}

std::tuple<bool, sBssidVapId&> tlvVsBssidIfaceMapping::bssid_vap_id_map(size_t idx) {
    bool ret_success = ( (m_bssid_vap_id_map_idx__ > 0) && (m_bssid_vap_id_map_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_bssid_vap_id_map[ret_idx]);
}

bool tlvVsBssidIfaceMapping::alloc_bssid_vap_id_map(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bssid_vap_id_map, abort!";
        return false;
    }
    size_t len = sizeof(sBssidVapId) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_bssid_vap_id_map[*m_bssid_vap_id_map_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_bssid_vap_id_map_idx__ += count;
    *m_bssid_vap_id_map_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if (!m_parse__) { 
        for (size_t i = m_bssid_vap_id_map_idx__ - count; i < m_bssid_vap_id_map_idx__; i++) { m_bssid_vap_id_map[i].struct_init(); }
    }
    return true;
}

void tlvVsBssidIfaceMapping::class_swap()
{
    tlvf_swap(8*sizeof(eActionOp_1905_VS), reinterpret_cast<uint8_t*>(m_action_op));
    for (size_t i = 0; i < m_bssid_vap_id_map_idx__; i++){
        m_bssid_vap_id_map[i].struct_swap();
    }
}

bool tlvVsBssidIfaceMapping::finalize()
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

size_t tlvVsBssidIfaceMapping::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // bssid_vap_id_map_length
    return class_size;
}

bool tlvVsBssidIfaceMapping::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_bssid_vap_id_map_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_bssid_vap_id_map_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_bssid_vap_id_map = reinterpret_cast<sBssidVapId*>(m_buff_ptr__);
    uint8_t bssid_vap_id_map_length = *m_bssid_vap_id_map_length;
    m_bssid_vap_id_map_idx__ = bssid_vap_id_map_length;
    if (!buffPtrIncrementSafe(sizeof(sBssidVapId) * (bssid_vap_id_map_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sBssidVapId) * (bssid_vap_id_map_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}

tlvVsDeviceInformation::tlvVsDeviceInformation(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvVsDeviceInformation::tlvVsDeviceInformation(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvVsDeviceInformation::~tlvVsDeviceInformation() {
}
sMacAddr& tlvVsDeviceInformation::al_mac() {
    return (sMacAddr&)(*m_al_mac);
}

uint8_t& tlvVsDeviceInformation::radio_mac_list_length() {
    return (uint8_t&)(*m_radio_mac_list_length);
}

std::tuple<bool, sMacAddr&> tlvVsDeviceInformation::radio_mac_list(size_t idx) {
    bool ret_success = ( (m_radio_mac_list_idx__ > 0) && (m_radio_mac_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_radio_mac_list[ret_idx]);
}

bool tlvVsDeviceInformation::alloc_radio_mac_list(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list radio_mac_list, abort!";
        return false;
    }
    size_t len = sizeof(sMacAddr) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_radio_mac_list[*m_radio_mac_list_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_radio_mac_list_idx__ += count;
    *m_radio_mac_list_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if (!m_parse__) { 
        for (size_t i = m_radio_mac_list_idx__ - count; i < m_radio_mac_list_idx__; i++) { m_radio_mac_list[i].struct_init(); }
    }
    return true;
}

void tlvVsDeviceInformation::class_swap()
{
    tlvf_swap(8*sizeof(eActionOp_1905_VS), reinterpret_cast<uint8_t*>(m_action_op));
    m_al_mac->struct_swap();
    for (size_t i = 0; i < m_radio_mac_list_idx__; i++){
        m_radio_mac_list[i].struct_swap();
    }
}

bool tlvVsDeviceInformation::finalize()
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

size_t tlvVsDeviceInformation::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // al_mac
    class_size += sizeof(uint8_t); // radio_mac_list_length
    return class_size;
}

bool tlvVsDeviceInformation::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_al_mac = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_al_mac->struct_init(); }
    m_radio_mac_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_radio_mac_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_radio_mac_list = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    uint8_t radio_mac_list_length = *m_radio_mac_list_length;
    m_radio_mac_list_idx__ = radio_mac_list_length;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr) * (radio_mac_list_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) * (radio_mac_list_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


