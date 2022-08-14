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

#include <tlvf/WEC/WEC_Attributes.h>
#include <tlvf/tlvflogging.h>

using namespace WEC;

cDppAttrInitiatorCapabilities::cDppAttrInitiatorCapabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrInitiatorCapabilities::cDppAttrInitiatorCapabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrInitiatorCapabilities::~cDppAttrInitiatorCapabilities() {
}
eWecDppAttributes& cDppAttrInitiatorCapabilities::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint8_t& cDppAttrInitiatorCapabilities::length() {
    return (const uint8_t&)(*m_length);
}

cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield& cDppAttrInitiatorCapabilities::initiator_capabilities() {
    return (cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield&)(*m_initiator_capabilities);
}

void cDppAttrInitiatorCapabilities::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    m_initiator_capabilities->struct_swap();
}

bool cDppAttrInitiatorCapabilities::finalize()
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

size_t cDppAttrInitiatorCapabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint8_t); // length
    class_size += sizeof(cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield); // initiator_capabilities
    return class_size;
}

bool cDppAttrInitiatorCapabilities::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_INITIATOR_CAPABILITIES;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0x1;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_initiator_capabilities = reinterpret_cast<cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_initiator_capabilities->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrResponderCapabilities::cDppAttrResponderCapabilities(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrResponderCapabilities::cDppAttrResponderCapabilities(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrResponderCapabilities::~cDppAttrResponderCapabilities() {
}
eWecDppAttributes& cDppAttrResponderCapabilities::type() {
    return (eWecDppAttributes&)(*m_type);
}

uint8_t& cDppAttrResponderCapabilities::length() {
    return (uint8_t&)(*m_length);
}

cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield& cDppAttrResponderCapabilities::responder_capabilities() {
    return (cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield&)(*m_responder_capabilities);
}

void cDppAttrResponderCapabilities::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    m_responder_capabilities->struct_swap();
}

bool cDppAttrResponderCapabilities::finalize()
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

size_t cDppAttrResponderCapabilities::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint8_t); // length
    class_size += sizeof(cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield); // responder_capabilities
    return class_size;
}

bool cDppAttrResponderCapabilities::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_RESPONDER_CAPABILITIES;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_responder_capabilities = reinterpret_cast<cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_responder_capabilities->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrWrappedDataAttribute::cDppAttrWrappedDataAttribute(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrWrappedDataAttribute::cDppAttrWrappedDataAttribute(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrWrappedDataAttribute::~cDppAttrWrappedDataAttribute() {
}
eWecDppAttributes& cDppAttrWrappedDataAttribute::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrWrappedDataAttribute::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t* cDppAttrWrappedDataAttribute::wrapped_data(size_t idx) {
    if ( (m_wrapped_data_idx__ == 0) || (m_wrapped_data_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_wrapped_data[idx]);
}

bool cDppAttrWrappedDataAttribute::set_wrapped_data(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_wrapped_data received a null pointer.";
        return false;
    }
    if (m_wrapped_data_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_wrapped_data was already allocated!";
        return false;
    }
    if (!alloc_wrapped_data(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_wrapped_data);
    return true;
}
bool cDppAttrWrappedDataAttribute::alloc_wrapped_data(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list wrapped_data, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_wrapped_data[m_wrapped_data_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_wrapped_data_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrWrappedDataAttribute::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrWrappedDataAttribute::finalize()
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

size_t cDppAttrWrappedDataAttribute::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrWrappedDataAttribute::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_WRAPPED_DATA;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_wrapped_data = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_wrapped_data_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrInitiatorAuthenticatingTag::cDppAttrInitiatorAuthenticatingTag(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrInitiatorAuthenticatingTag::cDppAttrInitiatorAuthenticatingTag(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrInitiatorAuthenticatingTag::~cDppAttrInitiatorAuthenticatingTag() {
}
eWecDppAttributes& cDppAttrInitiatorAuthenticatingTag::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrInitiatorAuthenticatingTag::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t* cDppAttrInitiatorAuthenticatingTag::initiator_authenticating_tag(size_t idx) {
    if ( (m_initiator_authenticating_tag_idx__ == 0) || (m_initiator_authenticating_tag_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_initiator_authenticating_tag[idx]);
}

bool cDppAttrInitiatorAuthenticatingTag::set_initiator_authenticating_tag(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_initiator_authenticating_tag received a null pointer.";
        return false;
    }
    if (m_initiator_authenticating_tag_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_initiator_authenticating_tag was already allocated!";
        return false;
    }
    if (!alloc_initiator_authenticating_tag(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_initiator_authenticating_tag);
    return true;
}
bool cDppAttrInitiatorAuthenticatingTag::alloc_initiator_authenticating_tag(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list initiator_authenticating_tag, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_initiator_authenticating_tag[m_initiator_authenticating_tag_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_initiator_authenticating_tag_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrInitiatorAuthenticatingTag::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrInitiatorAuthenticatingTag::finalize()
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

size_t cDppAttrInitiatorAuthenticatingTag::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrInitiatorAuthenticatingTag::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_INITIATOR_AUTHENTICATING_TAG;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_initiator_authenticating_tag = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_initiator_authenticating_tag_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrResponderAuthenticatingTag::cDppAttrResponderAuthenticatingTag(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrResponderAuthenticatingTag::cDppAttrResponderAuthenticatingTag(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrResponderAuthenticatingTag::~cDppAttrResponderAuthenticatingTag() {
}
eWecDppAttributes& cDppAttrResponderAuthenticatingTag::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrResponderAuthenticatingTag::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t* cDppAttrResponderAuthenticatingTag::responder_authenticating_tag(size_t idx) {
    if ( (m_responder_authenticating_tag_idx__ == 0) || (m_responder_authenticating_tag_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_responder_authenticating_tag[idx]);
}

bool cDppAttrResponderAuthenticatingTag::set_responder_authenticating_tag(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_responder_authenticating_tag received a null pointer.";
        return false;
    }
    if (m_responder_authenticating_tag_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_responder_authenticating_tag was already allocated!";
        return false;
    }
    if (!alloc_responder_authenticating_tag(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_responder_authenticating_tag);
    return true;
}
bool cDppAttrResponderAuthenticatingTag::alloc_responder_authenticating_tag(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list responder_authenticating_tag, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_responder_authenticating_tag[m_responder_authenticating_tag_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_responder_authenticating_tag_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrResponderAuthenticatingTag::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrResponderAuthenticatingTag::finalize()
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

size_t cDppAttrResponderAuthenticatingTag::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrResponderAuthenticatingTag::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_RESPONDER_AUTHENTICATING_TAG;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_responder_authenticating_tag = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_responder_authenticating_tag_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrDppConfigurationObject::cDppAttrDppConfigurationObject(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrDppConfigurationObject::cDppAttrDppConfigurationObject(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrDppConfigurationObject::~cDppAttrDppConfigurationObject() {
}
eWecDppAttributes& cDppAttrDppConfigurationObject::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrDppConfigurationObject::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrDppConfigurationObject::configuration_object_str() {
    char *configuration_object_ = configuration_object();
    if (!configuration_object_) { return std::string(); }
    auto str = std::string(configuration_object_, m_configuration_object_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrDppConfigurationObject::configuration_object(size_t length) {
    if( (m_configuration_object_idx__ == 0) || (m_configuration_object_idx__ < length) ) {
        TLVF_LOG(ERROR) << "configuration_object length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_configuration_object);
}

bool cDppAttrDppConfigurationObject::set_configuration_object(const std::string& str) { return set_configuration_object(str.c_str(), str.size()); }
bool cDppAttrDppConfigurationObject::set_configuration_object(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_configuration_object received a null pointer.";
        return false;
    }
    if (m_configuration_object_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_configuration_object was already allocated!";
        return false;
    }
    if (!alloc_configuration_object(size)) { return false; }
    std::copy(str, str + size, m_configuration_object);
    return true;
}
bool cDppAttrDppConfigurationObject::alloc_configuration_object(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list configuration_object, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_configuration_object[m_configuration_object_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_configuration_object_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrDppConfigurationObject::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrDppConfigurationObject::finalize()
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

size_t cDppAttrDppConfigurationObject::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrDppConfigurationObject::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_DPP_CONFIGURATION_OBJECT;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_configuration_object = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_configuration_object_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrDppConnector::cDppAttrDppConnector(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrDppConnector::cDppAttrDppConnector(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrDppConnector::~cDppAttrDppConnector() {
}
eWecDppAttributes& cDppAttrDppConnector::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrDppConnector::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrDppConnector::connector_str() {
    char *connector_ = connector();
    if (!connector_) { return std::string(); }
    auto str = std::string(connector_, m_connector_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrDppConnector::connector(size_t length) {
    if( (m_connector_idx__ == 0) || (m_connector_idx__ < length) ) {
        TLVF_LOG(ERROR) << "connector length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_connector);
}

bool cDppAttrDppConnector::set_connector(const std::string& str) { return set_connector(str.c_str(), str.size()); }
bool cDppAttrDppConnector::set_connector(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_connector received a null pointer.";
        return false;
    }
    if (m_connector_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_connector was already allocated!";
        return false;
    }
    if (!alloc_connector(size)) { return false; }
    std::copy(str, str + size, m_connector);
    return true;
}
bool cDppAttrDppConnector::alloc_connector(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list connector, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_connector[m_connector_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_connector_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrDppConnector::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrDppConnector::finalize()
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

size_t cDppAttrDppConnector::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrDppConnector::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_DPP_CONNECTOR;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_connector = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_connector_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrDppConfigurationRequestObject::cDppAttrDppConfigurationRequestObject(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrDppConfigurationRequestObject::cDppAttrDppConfigurationRequestObject(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrDppConfigurationRequestObject::~cDppAttrDppConfigurationRequestObject() {
}
eWecDppAttributes& cDppAttrDppConfigurationRequestObject::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrDppConfigurationRequestObject::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrDppConfigurationRequestObject::configuration_request_object_str() {
    char *configuration_request_object_ = configuration_request_object();
    if (!configuration_request_object_) { return std::string(); }
    auto str = std::string(configuration_request_object_, m_configuration_request_object_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrDppConfigurationRequestObject::configuration_request_object(size_t length) {
    if( (m_configuration_request_object_idx__ == 0) || (m_configuration_request_object_idx__ < length) ) {
        TLVF_LOG(ERROR) << "configuration_request_object length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_configuration_request_object);
}

bool cDppAttrDppConfigurationRequestObject::set_configuration_request_object(const std::string& str) { return set_configuration_request_object(str.c_str(), str.size()); }
bool cDppAttrDppConfigurationRequestObject::set_configuration_request_object(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_configuration_request_object received a null pointer.";
        return false;
    }
    if (m_configuration_request_object_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_configuration_request_object was already allocated!";
        return false;
    }
    if (!alloc_configuration_request_object(size)) { return false; }
    std::copy(str, str + size, m_configuration_request_object);
    return true;
}
bool cDppAttrDppConfigurationRequestObject::alloc_configuration_request_object(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list configuration_request_object, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_configuration_request_object[m_configuration_request_object_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_configuration_request_object_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrDppConfigurationRequestObject::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrDppConfigurationRequestObject::finalize()
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

size_t cDppAttrDppConfigurationRequestObject::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrDppConfigurationRequestObject::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_DPP_CONFIGURATION_REQUEST_OBJECT;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_configuration_request_object = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_configuration_request_object_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrBootstrappingKey::cDppAttrBootstrappingKey(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrBootstrappingKey::cDppAttrBootstrappingKey(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrBootstrappingKey::~cDppAttrBootstrappingKey() {
}
eWecDppAttributes& cDppAttrBootstrappingKey::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrBootstrappingKey::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrBootstrappingKey::configuration_request_object_str() {
    char *configuration_request_object_ = configuration_request_object();
    if (!configuration_request_object_) { return std::string(); }
    auto str = std::string(configuration_request_object_, m_configuration_request_object_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrBootstrappingKey::configuration_request_object(size_t length) {
    if( (m_configuration_request_object_idx__ == 0) || (m_configuration_request_object_idx__ < length) ) {
        TLVF_LOG(ERROR) << "configuration_request_object length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_configuration_request_object);
}

bool cDppAttrBootstrappingKey::set_configuration_request_object(const std::string& str) { return set_configuration_request_object(str.c_str(), str.size()); }
bool cDppAttrBootstrappingKey::set_configuration_request_object(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_configuration_request_object received a null pointer.";
        return false;
    }
    if (m_configuration_request_object_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_configuration_request_object was already allocated!";
        return false;
    }
    if (!alloc_configuration_request_object(size)) { return false; }
    std::copy(str, str + size, m_configuration_request_object);
    return true;
}
bool cDppAttrBootstrappingKey::alloc_configuration_request_object(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list configuration_request_object, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_configuration_request_object[m_configuration_request_object_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_configuration_request_object_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrBootstrappingKey::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrBootstrappingKey::finalize()
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

size_t cDppAttrBootstrappingKey::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrBootstrappingKey::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_BOOTSTRAPPING_KEY;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_configuration_request_object = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_configuration_request_object_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrCodeIdentifier::cDppAttrCodeIdentifier(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrCodeIdentifier::cDppAttrCodeIdentifier(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrCodeIdentifier::~cDppAttrCodeIdentifier() {
}
eWecDppAttributes& cDppAttrCodeIdentifier::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrCodeIdentifier::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrCodeIdentifier::code_identifier_str() {
    char *code_identifier_ = code_identifier();
    if (!code_identifier_) { return std::string(); }
    auto str = std::string(code_identifier_, m_code_identifier_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrCodeIdentifier::code_identifier(size_t length) {
    if( (m_code_identifier_idx__ == 0) || (m_code_identifier_idx__ < length) ) {
        TLVF_LOG(ERROR) << "code_identifier length is smaller than requested length";
        return nullptr;
    }
    if (m_code_identifier_idx__ > WEC_CODE_IDENTIFIER_MAX_LENGTH )  {
        TLVF_LOG(ERROR) << "Invalid length -  " << m_code_identifier_idx__ << " elements (max length is " << WEC_CODE_IDENTIFIER_MAX_LENGTH << ")";
        return nullptr;
    }
    return ((char*)m_code_identifier);
}

bool cDppAttrCodeIdentifier::set_code_identifier(const std::string& str) { return set_code_identifier(str.c_str(), str.size()); }
bool cDppAttrCodeIdentifier::set_code_identifier(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_code_identifier received a null pointer.";
        return false;
    }
    if (m_code_identifier_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_code_identifier was already allocated!";
        return false;
    }
    if (!alloc_code_identifier(size)) { return false; }
    std::copy(str, str + size, m_code_identifier);
    return true;
}
bool cDppAttrCodeIdentifier::alloc_code_identifier(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list code_identifier, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    if (m_code_identifier_idx__ + count > WEC_CODE_IDENTIFIER_MAX_LENGTH )  {
        TLVF_LOG(ERROR) << "Can't allocate " << count << " elements (max length is " << WEC_CODE_IDENTIFIER_MAX_LENGTH << " current length is " << m_code_identifier_idx__ << ")";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_code_identifier[m_code_identifier_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_code_identifier_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrCodeIdentifier::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrCodeIdentifier::finalize()
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

size_t cDppAttrCodeIdentifier::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrCodeIdentifier::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_CODE_IDENTIFIER;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_code_identifier = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_code_identifier_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrBootstrappingInfo::cDppAttrBootstrappingInfo(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrBootstrappingInfo::cDppAttrBootstrappingInfo(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrBootstrappingInfo::~cDppAttrBootstrappingInfo() {
}
eWecDppAttributes& cDppAttrBootstrappingInfo::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrBootstrappingInfo::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrBootstrappingInfo::bootstrapping_info_str() {
    char *bootstrapping_info_ = bootstrapping_info();
    if (!bootstrapping_info_) { return std::string(); }
    auto str = std::string(bootstrapping_info_, m_bootstrapping_info_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrBootstrappingInfo::bootstrapping_info(size_t length) {
    if( (m_bootstrapping_info_idx__ == 0) || (m_bootstrapping_info_idx__ < length) ) {
        TLVF_LOG(ERROR) << "bootstrapping_info length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_bootstrapping_info);
}

bool cDppAttrBootstrappingInfo::set_bootstrapping_info(const std::string& str) { return set_bootstrapping_info(str.c_str(), str.size()); }
bool cDppAttrBootstrappingInfo::set_bootstrapping_info(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_bootstrapping_info received a null pointer.";
        return false;
    }
    if (m_bootstrapping_info_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_bootstrapping_info was already allocated!";
        return false;
    }
    if (!alloc_bootstrapping_info(size)) { return false; }
    std::copy(str, str + size, m_bootstrapping_info);
    return true;
}
bool cDppAttrBootstrappingInfo::alloc_bootstrapping_info(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list bootstrapping_info, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_bootstrapping_info[m_bootstrapping_info_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_bootstrapping_info_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrBootstrappingInfo::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrBootstrappingInfo::finalize()
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

size_t cDppAttrBootstrappingInfo::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrBootstrappingInfo::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_BOOTSTRAPPING_INFO;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_bootstrapping_info = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_bootstrapping_info_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrDppEnvelopedData::cDppAttrDppEnvelopedData(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrDppEnvelopedData::cDppAttrDppEnvelopedData(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrDppEnvelopedData::~cDppAttrDppEnvelopedData() {
}
eWecDppAttributes& cDppAttrDppEnvelopedData::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrDppEnvelopedData::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t* cDppAttrDppEnvelopedData::enveloped_data(size_t idx) {
    if ( (m_enveloped_data_idx__ == 0) || (m_enveloped_data_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_enveloped_data[idx]);
}

bool cDppAttrDppEnvelopedData::set_enveloped_data(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_enveloped_data received a null pointer.";
        return false;
    }
    if (m_enveloped_data_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_enveloped_data was already allocated!";
        return false;
    }
    if (!alloc_enveloped_data(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_enveloped_data);
    return true;
}
bool cDppAttrDppEnvelopedData::alloc_enveloped_data(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list enveloped_data, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_enveloped_data[m_enveloped_data_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_enveloped_data_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrDppEnvelopedData::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrDppEnvelopedData::finalize()
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

size_t cDppAttrDppEnvelopedData::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrDppEnvelopedData::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_DPP_ENVELOPED_DATA;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_enveloped_data = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_enveloped_data_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrDppConnectionStatusObject::cDppAttrDppConnectionStatusObject(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrDppConnectionStatusObject::cDppAttrDppConnectionStatusObject(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrDppConnectionStatusObject::~cDppAttrDppConnectionStatusObject() {
}
eWecDppAttributes& cDppAttrDppConnectionStatusObject::type() {
    return (eWecDppAttributes&)(*m_type);
}

const uint16_t& cDppAttrDppConnectionStatusObject::length() {
    return (const uint16_t&)(*m_length);
}

std::string cDppAttrDppConnectionStatusObject::dpp_connection_status_json_object_str() {
    char *dpp_connection_status_json_object_ = dpp_connection_status_json_object();
    if (!dpp_connection_status_json_object_) { return std::string(); }
    auto str = std::string(dpp_connection_status_json_object_, m_dpp_connection_status_json_object_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDppAttrDppConnectionStatusObject::dpp_connection_status_json_object(size_t length) {
    if( (m_dpp_connection_status_json_object_idx__ == 0) || (m_dpp_connection_status_json_object_idx__ < length) ) {
        TLVF_LOG(ERROR) << "dpp_connection_status_json_object length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_dpp_connection_status_json_object);
}

bool cDppAttrDppConnectionStatusObject::set_dpp_connection_status_json_object(const std::string& str) { return set_dpp_connection_status_json_object(str.c_str(), str.size()); }
bool cDppAttrDppConnectionStatusObject::set_dpp_connection_status_json_object(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_dpp_connection_status_json_object received a null pointer.";
        return false;
    }
    if (m_dpp_connection_status_json_object_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_dpp_connection_status_json_object was already allocated!";
        return false;
    }
    if (!alloc_dpp_connection_status_json_object(size)) { return false; }
    std::copy(str, str + size, m_dpp_connection_status_json_object);
    return true;
}
bool cDppAttrDppConnectionStatusObject::alloc_dpp_connection_status_json_object(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list dpp_connection_status_json_object, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_dpp_connection_status_json_object[m_dpp_connection_status_json_object_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_dpp_connection_status_json_object_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(m_length){ (*m_length) += len; }
    return true;
}

void cDppAttrDppConnectionStatusObject::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrDppConnectionStatusObject::finalize()
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

size_t cDppAttrDppConnectionStatusObject::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrDppConnectionStatusObject::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_CONN_STATUS_OBJECT;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_dpp_connection_status_json_object = reinterpret_cast<char*>(m_buff_ptr__);
    if (m_length && m_parse__) {
        auto swap_len = *m_length;
        tlvf_swap((sizeof(swap_len) * 8), reinterpret_cast<uint8_t*>(&swap_len));
        size_t len = swap_len;
        len -= (m_buff_ptr__ - sizeof(*m_type) - sizeof(*m_length) - m_buff__);
        m_dpp_connection_status_json_object_idx__ = len/sizeof(char);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrReconfigurationFlags::cDppAttrReconfigurationFlags(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrReconfigurationFlags::cDppAttrReconfigurationFlags(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrReconfigurationFlags::~cDppAttrReconfigurationFlags() {
}
eWecDppAttributes& cDppAttrReconfigurationFlags::type() {
    return (eWecDppAttributes&)(*m_type);
}

uint8_t& cDppAttrReconfigurationFlags::length() {
    return (uint8_t&)(*m_length);
}

cDppAttrReconfigurationFlags::sWecReconfigurationFlags& cDppAttrReconfigurationFlags::reconfiguration_flags() {
    return (cDppAttrReconfigurationFlags::sWecReconfigurationFlags&)(*m_reconfiguration_flags);
}

void cDppAttrReconfigurationFlags::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    m_reconfiguration_flags->struct_swap();
}

bool cDppAttrReconfigurationFlags::finalize()
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

size_t cDppAttrReconfigurationFlags::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint8_t); // length
    class_size += sizeof(cDppAttrReconfigurationFlags::sWecReconfigurationFlags); // reconfiguration_flags
    return class_size;
}

bool cDppAttrReconfigurationFlags::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_RECONFIGURATION_FLAGS;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_length = 0x1;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_reconfiguration_flags = reinterpret_cast<cDppAttrReconfigurationFlags::sWecReconfigurationFlags*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(cDppAttrReconfigurationFlags::sWecReconfigurationFlags))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(cDppAttrReconfigurationFlags::sWecReconfigurationFlags) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_reconfiguration_flags->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}

cDppAttrEtagId::cDppAttrEtagId(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDppAttrEtagId::cDppAttrEtagId(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDppAttrEtagId::~cDppAttrEtagId() {
}
eWecDppAttributes& cDppAttrEtagId::type() {
    return (eWecDppAttributes&)(*m_type);
}

uint16_t& cDppAttrEtagId::length() {
    return (uint16_t&)(*m_length);
}

uint8_t* cDppAttrEtagId::etag_id(size_t idx) {
    if ( (m_etag_id_idx__ == 0) || (m_etag_id_idx__ <= idx) ) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
        return nullptr;
    }
    return &(m_etag_id[idx]);
}

bool cDppAttrEtagId::set_etag_id(const void* buffer, size_t size) {
    if (buffer == nullptr) {
        TLVF_LOG(WARNING) << "set_etag_id received a null pointer.";
        return false;
    }
    if (m_etag_id_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_etag_id was already allocated!";
        return false;
    }
    if (!alloc_etag_id(size)) { return false; }
    std::copy_n(reinterpret_cast<const uint8_t *>(buffer), size, m_etag_id);
    return true;
}
bool cDppAttrEtagId::alloc_etag_id(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list etag_id, abort!";
        return false;
    }
    size_t len = sizeof(uint8_t) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_etag_id[m_etag_id_idx__];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_etag_id_idx__ += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

void cDppAttrEtagId::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_type));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

bool cDppAttrEtagId::finalize()
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

size_t cDppAttrEtagId::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eWecDppAttributes); // type
    class_size += sizeof(uint16_t); // length
    return class_size;
}

bool cDppAttrEtagId::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eWecDppAttributes*>(m_buff_ptr__);
    if (!m_parse__) *m_type = ATTR_E_TAG_ID;
    if (!buffPtrIncrementSafe(sizeof(eWecDppAttributes))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(eWecDppAttributes) << ") Failed!";
        return false;
    }
    m_length = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_etag_id = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (m_parse__) {
        size_t len = getBuffRemainingBytes();
        m_etag_id_idx__ = len/sizeof(uint8_t);
        if (!buffPtrIncrementSafe(len)) {
            LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
            return false;
        }
    }
    if (m_parse__) { class_swap(); }
    return true;
}


