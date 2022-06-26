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

#include <tlvf/wfa_map/tlvTeamMembers.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvTeamMembers::tlvTeamMembers(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvTeamMembers::tlvTeamMembers(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvTeamMembers::~tlvTeamMembers() {
}
const eTlvTypeMap& tlvTeamMembers::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvTeamMembers::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvTeamMembers::team_list_length() {
    return (uint8_t&)(*m_team_list_length);
}

std::tuple<bool, cTeamDetails&> tlvTeamMembers::team_details_list(size_t idx) {
    bool ret_success = ( (m_team_details_list_idx__ > 0) && (m_team_details_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_team_details_list_vector[ret_idx]));
}

std::shared_ptr<cTeamDetails> tlvTeamMembers::create_team_details_list() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list team_details_list, abort!";
        return nullptr;
    }
    size_t len = cTeamDetails::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 0;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_team_details_list;
    if (m_team_details_list_idx__ > 0) {
        src = (uint8_t *)m_team_details_list_vector[m_team_details_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cTeamDetails>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvTeamMembers::add_team_details_list(std::shared_ptr<cTeamDetails> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_team_details_list was called before add_team_details_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_team_details_list;
    if (m_team_details_list_idx__ > 0) {
        src = (uint8_t *)m_team_details_list_vector[m_team_details_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_team_details_list_idx__++;
    if (!m_parse__) { (*m_team_list_length)++; }
    size_t len = ptr->getLen();
    m_team_details_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvTeamMembers::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_team_details_list_idx__; i++){
        std::get<1>(team_details_list(i)).class_swap();
    }
}

bool tlvTeamMembers::finalize()
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

size_t tlvTeamMembers::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // team_list_length
    return class_size;
}

bool tlvTeamMembers::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_TEAM_MEMBERS;
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
    m_team_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_team_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_team_details_list = reinterpret_cast<cTeamDetails*>(m_buff_ptr__);
    uint8_t team_list_length = *m_team_list_length;
    m_team_details_list_idx__ = 0;
    for (size_t i = 0; i < team_list_length; i++) {
        auto team_details_list = create_team_details_list();
        if (!team_details_list || !team_details_list->isInitialized()) {
            TLVF_LOG(ERROR) << "create_team_details_list() failed";
            return false;
        }
        if (!add_team_details_list(team_details_list)) {
            TLVF_LOG(ERROR) << "add_team_details_list() failed";
            return false;
        }
        // swap back since team_details_list will be swapped as part of the whole class swap
        team_details_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_TEAM_MEMBERS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_TEAM_MEMBERS) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cTeamDetails::cTeamDetails(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cTeamDetails::cTeamDetails(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cTeamDetails::~cTeamDetails() {
}
std::string cTeamDetails::team_name_str() {
    char *team_name_ = team_name();
    if (!team_name_) { return std::string(); }
    auto str = std::string(team_name_, m_team_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cTeamDetails::team_name(size_t length) {
    if( (m_team_name_idx__ == 0) || (m_team_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "team_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_team_name);
}

bool cTeamDetails::set_team_name(const std::string& str) { return set_team_name(str.c_str(), str.size()); }
bool cTeamDetails::set_team_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_team_name received a null pointer.";
        return false;
    }
    if (size > 16) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than string length";
        return false;
    }
    std::copy(str, str + size, m_team_name);
    return true;
}
uint8_t& cTeamDetails::developer_list_length() {
    return (uint8_t&)(*m_developer_list_length);
}

std::tuple<bool, cDeveloperDetails&> cTeamDetails::developer_details_list(size_t idx) {
    bool ret_success = ( (m_developer_details_list_idx__ > 0) && (m_developer_details_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_developer_details_list_vector[ret_idx]));
}

std::shared_ptr<cDeveloperDetails> cTeamDetails::create_developer_details_list() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list developer_details_list, abort!";
        return nullptr;
    }
    size_t len = cDeveloperDetails::get_initial_size();
    if (m_lock_allocation__) {
        TLVF_LOG(ERROR) << "Can't create new element before adding the previous one";
        return nullptr;
    }
    if (getBuffRemainingBytes() < len) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return nullptr;
    }
    m_lock_order_counter__ = 0;
    m_lock_allocation__ = true;
    uint8_t *src = (uint8_t *)m_developer_details_list;
    if (m_developer_details_list_idx__ > 0) {
        src = (uint8_t *)m_developer_details_list_vector[m_developer_details_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cDeveloperDetails>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cTeamDetails::add_developer_details_list(std::shared_ptr<cDeveloperDetails> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_developer_details_list was called before add_developer_details_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_developer_details_list;
    if (m_developer_details_list_idx__ > 0) {
        src = (uint8_t *)m_developer_details_list_vector[m_developer_details_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_developer_details_list_idx__++;
    if (!m_parse__) { (*m_developer_list_length)++; }
    size_t len = ptr->getLen();
    m_developer_details_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cTeamDetails::class_swap()
{
    for (size_t i = 0; i < m_developer_details_list_idx__; i++){
        std::get<1>(developer_details_list(i)).class_swap();
    }
}

bool cTeamDetails::finalize()
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

size_t cTeamDetails::get_initial_size()
{
    size_t class_size = 0;
    class_size += 16 * sizeof(char); // team_name
    class_size += sizeof(uint8_t); // developer_list_length
    return class_size;
}

bool cTeamDetails::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_team_name = reinterpret_cast<char*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(char) * (16))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (16) << ") Failed!";
        return false;
    }
    m_team_name_idx__  = 16;
    m_developer_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_developer_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_developer_details_list = reinterpret_cast<cDeveloperDetails*>(m_buff_ptr__);
    uint8_t developer_list_length = *m_developer_list_length;
    m_developer_details_list_idx__ = 0;
    for (size_t i = 0; i < developer_list_length; i++) {
        auto developer_details_list = create_developer_details_list();
        if (!developer_details_list || !developer_details_list->isInitialized()) {
            TLVF_LOG(ERROR) << "create_developer_details_list() failed";
            return false;
        }
        if (!add_developer_details_list(developer_details_list)) {
            TLVF_LOG(ERROR) << "add_developer_details_list() failed";
            return false;
        }
        // swap back since developer_details_list will be swapped as part of the whole class swap
        developer_details_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDeveloperDetails::cDeveloperDetails(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDeveloperDetails::cDeveloperDetails(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDeveloperDetails::~cDeveloperDetails() {
}
uint8_t& cDeveloperDetails::developer_name_length() {
    return (uint8_t&)(*m_developer_name_length);
}

std::string cDeveloperDetails::developer_name_str() {
    char *developer_name_ = developer_name();
    if (!developer_name_) { return std::string(); }
    auto str = std::string(developer_name_, m_developer_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDeveloperDetails::developer_name(size_t length) {
    if( (m_developer_name_idx__ == 0) || (m_developer_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "developer_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_developer_name);
}

bool cDeveloperDetails::set_developer_name(const std::string& str) { return set_developer_name(str.c_str(), str.size()); }
bool cDeveloperDetails::set_developer_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_developer_name received a null pointer.";
        return false;
    }
    if (m_developer_name_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_developer_name was already allocated!";
        return false;
    }
    if (!alloc_developer_name(size)) { return false; }
    std::copy(str, str + size, m_developer_name);
    return true;
}
bool cDeveloperDetails::alloc_developer_name(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list developer_name, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_developer_name[*m_developer_name_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_value = (sValue *)((uint8_t *)(m_value) + len);
    m_age = (uint8_t *)((uint8_t *)(m_age) + len);
    m_previous_company_name_list_length = (uint8_t *)((uint8_t *)(m_previous_company_name_list_length) + len);
    m_previous_company_details_list = (cPreviousCompanyDetails *)((uint8_t *)(m_previous_company_details_list) + len);
    m_developer_name_idx__ += count;
    *m_developer_name_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

cDeveloperDetails::sValue& cDeveloperDetails::value() {
    return (sValue&)(*m_value);
}

uint8_t& cDeveloperDetails::age() {
    return (uint8_t&)(*m_age);
}

uint8_t& cDeveloperDetails::previous_company_name_list_length() {
    return (uint8_t&)(*m_previous_company_name_list_length);
}

std::tuple<bool, cPreviousCompanyDetails&> cDeveloperDetails::previous_company_details_list(size_t idx) {
    bool ret_success = ( (m_previous_company_details_list_idx__ > 0) && (m_previous_company_details_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_previous_company_details_list_vector[ret_idx]));
}

std::shared_ptr<cPreviousCompanyDetails> cDeveloperDetails::create_previous_company_details_list() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list previous_company_details_list, abort!";
        return nullptr;
    }
    size_t len = cPreviousCompanyDetails::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_previous_company_details_list;
    if (m_previous_company_details_list_idx__ > 0) {
        src = (uint8_t *)m_previous_company_details_list_vector[m_previous_company_details_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cPreviousCompanyDetails>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cDeveloperDetails::add_previous_company_details_list(std::shared_ptr<cPreviousCompanyDetails> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_previous_company_details_list was called before add_previous_company_details_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_previous_company_details_list;
    if (m_previous_company_details_list_idx__ > 0) {
        src = (uint8_t *)m_previous_company_details_list_vector[m_previous_company_details_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_previous_company_details_list_idx__++;
    if (!m_parse__) { (*m_previous_company_name_list_length)++; }
    size_t len = ptr->getLen();
    m_previous_company_details_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cDeveloperDetails::class_swap()
{
    m_value->struct_swap();
    for (size_t i = 0; i < m_previous_company_details_list_idx__; i++){
        std::get<1>(previous_company_details_list(i)).class_swap();
    }
}

bool cDeveloperDetails::finalize()
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

size_t cDeveloperDetails::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // developer_name_length
    class_size += sizeof(sValue); // value
    class_size += sizeof(uint8_t); // age
    class_size += sizeof(uint8_t); // previous_company_name_list_length
    return class_size;
}

bool cDeveloperDetails::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_developer_name_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_developer_name_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_developer_name = reinterpret_cast<char*>(m_buff_ptr__);
    uint8_t developer_name_length = *m_developer_name_length;
    m_developer_name_idx__ = developer_name_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (developer_name_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (developer_name_length) << ") Failed!";
        return false;
    }
    m_value = reinterpret_cast<sValue*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sValue))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sValue) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_value->struct_init(); }
    m_age = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_previous_company_name_list_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_previous_company_name_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_previous_company_details_list = reinterpret_cast<cPreviousCompanyDetails*>(m_buff_ptr__);
    uint8_t previous_company_name_list_length = *m_previous_company_name_list_length;
    m_previous_company_details_list_idx__ = 0;
    for (size_t i = 0; i < previous_company_name_list_length; i++) {
        auto previous_company_details_list = create_previous_company_details_list();
        if (!previous_company_details_list || !previous_company_details_list->isInitialized()) {
            TLVF_LOG(ERROR) << "create_previous_company_details_list() failed";
            return false;
        }
        if (!add_previous_company_details_list(previous_company_details_list)) {
            TLVF_LOG(ERROR) << "add_previous_company_details_list() failed";
            return false;
        }
        // swap back since previous_company_details_list will be swapped as part of the whole class swap
        previous_company_details_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cPreviousCompanyDetails::cPreviousCompanyDetails(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cPreviousCompanyDetails::cPreviousCompanyDetails(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cPreviousCompanyDetails::~cPreviousCompanyDetails() {
}
uint8_t& cPreviousCompanyDetails::company_name_length() {
    return (uint8_t&)(*m_company_name_length);
}

std::string cPreviousCompanyDetails::company_name_str() {
    char *company_name_ = company_name();
    if (!company_name_) { return std::string(); }
    auto str = std::string(company_name_, m_company_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cPreviousCompanyDetails::company_name(size_t length) {
    if( (m_company_name_idx__ == 0) || (m_company_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "company_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_company_name);
}

bool cPreviousCompanyDetails::set_company_name(const std::string& str) { return set_company_name(str.c_str(), str.size()); }
bool cPreviousCompanyDetails::set_company_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_company_name received a null pointer.";
        return false;
    }
    if (m_company_name_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_company_name was already allocated!";
        return false;
    }
    if (!alloc_company_name(size)) { return false; }
    std::copy(str, str + size, m_company_name);
    return true;
}
bool cPreviousCompanyDetails::alloc_company_name(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list company_name, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_company_name[*m_company_name_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_company_name_idx__ += count;
    *m_company_name_length += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

void cPreviousCompanyDetails::class_swap()
{
}

bool cPreviousCompanyDetails::finalize()
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

size_t cPreviousCompanyDetails::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // company_name_length
    return class_size;
}

bool cPreviousCompanyDetails::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_company_name_length = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_company_name_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_company_name = reinterpret_cast<char*>(m_buff_ptr__);
    uint8_t company_name_length = *m_company_name_length;
    m_company_name_idx__ = company_name_length;
    if (!buffPtrIncrementSafe(sizeof(char) * (company_name_length))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (company_name_length) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


