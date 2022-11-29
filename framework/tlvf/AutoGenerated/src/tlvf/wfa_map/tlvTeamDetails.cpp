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

#include <tlvf/wfa_map/tlvTeamDetails.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvTeamDetails::tlvTeamDetails(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvTeamDetails::tlvTeamDetails(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvTeamDetails::~tlvTeamDetails() {
}
const eTlvTypeMap& tlvTeamDetails::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvTeamDetails::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvTeamDetails::team_list_length() {
    return (uint8_t&)(*m_team_list_length);
}

std::tuple<bool, cTeamInfo&> tlvTeamDetails::team_list(size_t idx) {
    bool ret_success = ( (m_team_list_idx__ > 0) && (m_team_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_team_list_vector[ret_idx]));
}

std::shared_ptr<cTeamInfo> tlvTeamDetails::create_team_list() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list team_list, abort!";
        return nullptr;
    }
    size_t len = cTeamInfo::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_team_list;
    if (m_team_list_idx__ > 0) {
        src = (uint8_t *)m_team_list_vector[m_team_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cTeamInfo>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvTeamDetails::add_team_list(std::shared_ptr<cTeamInfo> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_team_list was called before add_team_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_team_list;
    if (m_team_list_idx__ > 0) {
        src = (uint8_t *)m_team_list_vector[m_team_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_team_list_idx__++;
    if (!m_parse__) { (*m_team_list_length)++; }
    size_t len = ptr->getLen();
    m_team_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvTeamDetails::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_team_list_idx__; i++){
        std::get<1>(team_list(i)).class_swap();
    }
}

bool tlvTeamDetails::finalize()
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

size_t tlvTeamDetails::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // team_list_length
    return class_size;
}

bool tlvTeamDetails::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_TEAM_DETAILS;
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
    m_team_list = reinterpret_cast<cTeamInfo*>(m_buff_ptr__);
    uint8_t team_list_length = *m_team_list_length;
    m_team_list_idx__ = 0;
    for (size_t i = 0; i < team_list_length; i++) {
        auto team_list = create_team_list();
        if (!team_list || !team_list->isInitialized()) {
            TLVF_LOG(ERROR) << "create_team_list() failed";
            return false;
        }
        if (!add_team_list(team_list)) {
            TLVF_LOG(ERROR) << "add_team_list() failed";
            return false;
        }
        // swap back since team_list will be swapped as part of the whole class swap
        team_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_TEAM_DETAILS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_TEAM_DETAILS) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cTeamInfo::cTeamInfo(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cTeamInfo::cTeamInfo(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cTeamInfo::~cTeamInfo() {
}
std::string cTeamInfo::team_name_str() {
    char *team_name_ = team_name();
    if (!team_name_) { return std::string(); }
    auto str = std::string(team_name_, m_team_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cTeamInfo::team_name(size_t length) {
    if( (m_team_name_idx__ == 0) || (m_team_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "team_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_team_name);
}

bool cTeamInfo::set_team_name(const std::string& str) { return set_team_name(str.c_str(), str.size()); }
bool cTeamInfo::set_team_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_team_name received a null pointer.";
        return false;
    }
    if (size > 8) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than string length";
        return false;
    }
    std::copy(str, str + size, m_team_name);
    return true;
}
std::string cTeamInfo::scrum_master_str() {
    char *scrum_master_ = scrum_master();
    if (!scrum_master_) { return std::string(); }
    auto str = std::string(scrum_master_, m_scrum_master_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cTeamInfo::scrum_master(size_t length) {
    if( (m_scrum_master_idx__ == 0) || (m_scrum_master_idx__ < length) ) {
        TLVF_LOG(ERROR) << "scrum_master length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_scrum_master);
}

bool cTeamInfo::set_scrum_master(const std::string& str) { return set_scrum_master(str.c_str(), str.size()); }
bool cTeamInfo::set_scrum_master(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_scrum_master received a null pointer.";
        return false;
    }
    if (size > 16) {
        TLVF_LOG(ERROR) << "Received buffer size is smaller than string length";
        return false;
    }
    std::copy(str, str + size, m_scrum_master);
    return true;
}
uint8_t& cTeamInfo::no_of_developer() {
    return (uint8_t&)(*m_no_of_developer);
}

std::tuple<bool, cDeveloper&> cTeamInfo::developer_list(size_t idx) {
    bool ret_success = ( (m_developer_list_idx__ > 0) && (m_developer_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_developer_list_vector[ret_idx]));
}

std::shared_ptr<cDeveloper> cTeamInfo::create_developer_list() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list developer_list, abort!";
        return nullptr;
    }
    size_t len = cDeveloper::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_developer_list;
    if (m_developer_list_idx__ > 0) {
        src = (uint8_t *)m_developer_list_vector[m_developer_list_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cDeveloper>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cTeamInfo::add_developer_list(std::shared_ptr<cDeveloper> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_developer_list was called before add_developer_list";
        return false;
    }
    uint8_t *src = (uint8_t *)m_developer_list;
    if (m_developer_list_idx__ > 0) {
        src = (uint8_t *)m_developer_list_vector[m_developer_list_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_developer_list_idx__++;
    if (!m_parse__) { (*m_no_of_developer)++; }
    size_t len = ptr->getLen();
    m_developer_list_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cTeamInfo::class_swap()
{
    for (size_t i = 0; i < m_developer_list_idx__; i++){
        std::get<1>(developer_list(i)).class_swap();
    }
}

bool cTeamInfo::finalize()
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

size_t cTeamInfo::get_initial_size()
{
    size_t class_size = 0;
    class_size += 8 * sizeof(char); // team_name
    class_size += 16 * sizeof(char); // scrum_master
    class_size += sizeof(uint8_t); // no_of_developer
    return class_size;
}

bool cTeamInfo::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_team_name = reinterpret_cast<char*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(char) * (8))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (8) << ") Failed!";
        return false;
    }
    m_team_name_idx__  = 8;
    m_scrum_master = reinterpret_cast<char*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(char) * (16))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (16) << ") Failed!";
        return false;
    }
    m_scrum_master_idx__  = 16;
    m_no_of_developer = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_no_of_developer = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_developer_list = reinterpret_cast<cDeveloper*>(m_buff_ptr__);
    uint8_t no_of_developer = *m_no_of_developer;
    m_developer_list_idx__ = 0;
    for (size_t i = 0; i < no_of_developer; i++) {
        auto developer_list = create_developer_list();
        if (!developer_list || !developer_list->isInitialized()) {
            TLVF_LOG(ERROR) << "create_developer_list() failed";
            return false;
        }
        if (!add_developer_list(developer_list)) {
            TLVF_LOG(ERROR) << "add_developer_list() failed";
            return false;
        }
        // swap back since developer_list will be swapped as part of the whole class swap
        developer_list->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDeveloper::cDeveloper(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDeveloper::cDeveloper(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDeveloper::~cDeveloper() {
}
uint8_t& cDeveloper::name_len() {
    return (uint8_t&)(*m_name_len);
}

std::string cDeveloper::name_str() {
    char *name_ = name();
    if (!name_) { return std::string(); }
    auto str = std::string(name_, m_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDeveloper::name(size_t length) {
    if( (m_name_idx__ == 0) || (m_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_name);
}

bool cDeveloper::set_name(const std::string& str) { return set_name(str.c_str(), str.size()); }
bool cDeveloper::set_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_name received a null pointer.";
        return false;
    }
    if (m_name_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_name was already allocated!";
        return false;
    }
    if (!alloc_name(size)) { return false; }
    std::copy(str, str + size, m_name);
    return true;
}
bool cDeveloper::alloc_name(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list name, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_name[*m_name_len];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_num_of_mr = (uint8_t *)((uint8_t *)(m_num_of_mr) + len);
    m_exp_and_loc = (sExp_and_loc *)((uint8_t *)(m_exp_and_loc) + len);
    m_name_idx__ += count;
    *m_name_len += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

uint8_t& cDeveloper::num_of_mr() {
    return (uint8_t&)(*m_num_of_mr);
}

cDeveloper::sExp_and_loc& cDeveloper::exp_and_loc() {
    return (sExp_and_loc&)(*m_exp_and_loc);
}

void cDeveloper::class_swap()
{
    m_exp_and_loc->struct_swap();
}

bool cDeveloper::finalize()
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

size_t cDeveloper::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // name_len
    class_size += sizeof(uint8_t); // num_of_mr
    class_size += sizeof(sExp_and_loc); // exp_and_loc
    return class_size;
}

bool cDeveloper::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_name_len = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_name_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_name = reinterpret_cast<char*>(m_buff_ptr__);
    uint8_t name_len = *m_name_len;
    m_name_idx__ = name_len;
    if (!buffPtrIncrementSafe(sizeof(char) * (name_len))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (name_len) << ") Failed!";
        return false;
    }
    m_num_of_mr = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_of_mr = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_exp_and_loc = reinterpret_cast<sExp_and_loc*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sExp_and_loc))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sExp_and_loc) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_exp_and_loc->struct_init(); }
    if (m_parse__) { class_swap(); }
    return true;
}


