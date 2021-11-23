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

#include <tlvf/wfa_map/tlvTeamsMembers.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvTeamsMembers::tlvTeamsMembers(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
tlvTeamsMembers::tlvTeamsMembers(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
tlvTeamsMembers::~tlvTeamsMembers() {
}
const eTlvTypeMap& tlvTeamsMembers::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvTeamsMembers::length() {
    return (const uint16_t&)(*m_length);
}

uint8_t& tlvTeamsMembers::team_id() {
    return (uint8_t&)(*m_team_id);
}

std::tuple<bool, cTeamProfile&> tlvTeamsMembers::team_profile(size_t idx) {
    bool ret_success = ( (m_team_profile_idx__ > 0) && (m_team_profile_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_team_profile_vector[ret_idx]));
}

std::shared_ptr<cTeamProfile> tlvTeamsMembers::create_team_profile() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list team_profile, abort!";
        return nullptr;
    }
    size_t len = cTeamProfile::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_team_profile;
    if (m_team_profile_idx__ > 0) {
        src = (uint8_t *)m_team_profile_vector[m_team_profile_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cTeamProfile>(src, getBuffRemainingBytes(src), m_parse__);
}

bool tlvTeamsMembers::add_team_profile(std::shared_ptr<cTeamProfile> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_team_profile was called before add_team_profile";
        return false;
    }
    uint8_t *src = (uint8_t *)m_team_profile;
    if (m_team_profile_idx__ > 0) {
        src = (uint8_t *)m_team_profile_vector[m_team_profile_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_team_profile_idx__++;
    if (!m_parse__) { (*m_team_id)++; }
    size_t len = ptr->getLen();
    m_team_profile_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    if(!m_parse__ && m_length){ (*m_length) += len; }
    m_lock_allocation__ = false;
    return true;
}

void tlvTeamsMembers::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    for (size_t i = 0; i < m_team_profile_idx__; i++){
        std::get<1>(team_profile(i)).class_swap();
    }
}

bool tlvTeamsMembers::finalize()
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

size_t tlvTeamsMembers::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(uint8_t); // team_id
    return class_size;
}

bool tlvTeamsMembers::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = reinterpret_cast<eTlvTypeMap*>(m_buff_ptr__);
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_TEAMS_MEMBERS;
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
    m_team_id = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_team_id = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_team_profile = reinterpret_cast<cTeamProfile*>(m_buff_ptr__);
    uint8_t team_id = *m_team_id;
    m_team_profile_idx__ = 0;
    for (size_t i = 0; i < team_id; i++) {
        auto team_profile = create_team_profile();
        if (!team_profile) {
            TLVF_LOG(ERROR) << "create_team_profile() failed";
            return false;
        }
        if (!add_team_profile(team_profile)) {
            TLVF_LOG(ERROR) << "add_team_profile() failed";
            return false;
        }
        // swap back since team_profile will be swapped as part of the whole class swap
        team_profile->class_swap();
    }
    if (m_parse__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_TEAMS_MEMBERS) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_TEAMS_MEMBERS) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}

cTeamProfile::cTeamProfile(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cTeamProfile::cTeamProfile(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cTeamProfile::~cTeamProfile() {
}
std::string cTeamProfile::team_name_str() {
    char *team_name_ = team_name();
    if (!team_name_) { return std::string(); }
    auto str = std::string(team_name_, m_team_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cTeamProfile::team_name(size_t length) {
    if( (m_team_name_idx__ == 0) || (m_team_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "team_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_team_name);
}

bool cTeamProfile::set_team_name(const std::string& str) { return set_team_name(str.c_str(), str.size()); }
bool cTeamProfile::set_team_name(const char str[], size_t size) {
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
uint8_t& cTeamProfile::num_of_dev() {
    return (uint8_t&)(*m_num_of_dev);
}

std::tuple<bool, cDevProfile&> cTeamProfile::dev_profile(size_t idx) {
    bool ret_success = ( (m_dev_profile_idx__ > 0) && (m_dev_profile_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_dev_profile_vector[ret_idx]));
}

std::shared_ptr<cDevProfile> cTeamProfile::create_dev_profile() {
    if (m_lock_order_counter__ > 0) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list dev_profile, abort!";
        return nullptr;
    }
    size_t len = cDevProfile::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_dev_profile;
    if (m_dev_profile_idx__ > 0) {
        src = (uint8_t *)m_dev_profile_vector[m_dev_profile_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cDevProfile>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cTeamProfile::add_dev_profile(std::shared_ptr<cDevProfile> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_dev_profile was called before add_dev_profile";
        return false;
    }
    uint8_t *src = (uint8_t *)m_dev_profile;
    if (m_dev_profile_idx__ > 0) {
        src = (uint8_t *)m_dev_profile_vector[m_dev_profile_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_dev_profile_idx__++;
    if (!m_parse__) { (*m_num_of_dev)++; }
    size_t len = ptr->getLen();
    m_dev_profile_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cTeamProfile::class_swap()
{
    for (size_t i = 0; i < m_dev_profile_idx__; i++){
        std::get<1>(dev_profile(i)).class_swap();
    }
}

bool cTeamProfile::finalize()
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

size_t cTeamProfile::get_initial_size()
{
    size_t class_size = 0;
    class_size += 16 * sizeof(char); // team_name
    class_size += sizeof(uint8_t); // num_of_dev
    return class_size;
}

bool cTeamProfile::init()
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
    m_num_of_dev = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_num_of_dev = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_dev_profile = reinterpret_cast<cDevProfile*>(m_buff_ptr__);
    uint8_t num_of_dev = *m_num_of_dev;
    m_dev_profile_idx__ = 0;
    for (size_t i = 0; i < num_of_dev; i++) {
        auto dev_profile = create_dev_profile();
        if (!dev_profile) {
            TLVF_LOG(ERROR) << "create_dev_profile() failed";
            return false;
        }
        if (!add_dev_profile(dev_profile)) {
            TLVF_LOG(ERROR) << "add_dev_profile() failed";
            return false;
        }
        // swap back since dev_profile will be swapped as part of the whole class swap
        dev_profile->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cDevProfile::cDevProfile(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cDevProfile::cDevProfile(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cDevProfile::~cDevProfile() {
}
uint8_t& cDevProfile::dev_name_len() {
    return (uint8_t&)(*m_dev_name_len);
}

std::string cDevProfile::dev_name_str() {
    char *dev_name_ = dev_name();
    if (!dev_name_) { return std::string(); }
    auto str = std::string(dev_name_, m_dev_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cDevProfile::dev_name(size_t length) {
    if( (m_dev_name_idx__ == 0) || (m_dev_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "dev_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_dev_name);
}

bool cDevProfile::set_dev_name(const std::string& str) { return set_dev_name(str.c_str(), str.size()); }
bool cDevProfile::set_dev_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_dev_name received a null pointer.";
        return false;
    }
    if (m_dev_name_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_dev_name was already allocated!";
        return false;
    }
    if (!alloc_dev_name(size)) { return false; }
    std::copy(str, str + size, m_dev_name);
    return true;
}
bool cDevProfile::alloc_dev_name(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list dev_name, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_dev_name[*m_dev_name_len];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_work_exp = (sDevProfile *)((uint8_t *)(m_work_exp) + len);
    m_age = (uint8_t *)((uint8_t *)(m_age) + len);
    m_prev_comp_list_len = (uint8_t *)((uint8_t *)(m_prev_comp_list_len) + len);
    m_previous_companies = (cCompanyName *)((uint8_t *)(m_previous_companies) + len);
    m_dev_name_idx__ += count;
    *m_dev_name_len += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

cDevProfile::sDevProfile& cDevProfile::work_exp() {
    return (sDevProfile&)(*m_work_exp);
}

uint8_t& cDevProfile::age() {
    return (uint8_t&)(*m_age);
}

uint8_t& cDevProfile::prev_comp_list_len() {
    return (uint8_t&)(*m_prev_comp_list_len);
}

std::tuple<bool, cCompanyName&> cDevProfile::previous_companies(size_t idx) {
    bool ret_success = ( (m_previous_companies_idx__ > 0) && (m_previous_companies_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, *(m_previous_companies_vector[ret_idx]));
}

std::shared_ptr<cCompanyName> cDevProfile::create_previous_companies() {
    if (m_lock_order_counter__ > 1) {
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list previous_companies, abort!";
        return nullptr;
    }
    size_t len = cCompanyName::get_initial_size();
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
    uint8_t *src = (uint8_t *)m_previous_companies;
    if (m_previous_companies_idx__ > 0) {
        src = (uint8_t *)m_previous_companies_vector[m_previous_companies_idx__ - 1]->getBuffPtr();
    }
    if (!m_parse__) {
        uint8_t *dst = src + len;
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    return std::make_shared<cCompanyName>(src, getBuffRemainingBytes(src), m_parse__);
}

bool cDevProfile::add_previous_companies(std::shared_ptr<cCompanyName> ptr) {
    if (ptr == nullptr) {
        TLVF_LOG(ERROR) << "Received entry is nullptr";
        return false;
    }
    if (m_lock_allocation__ == false) {
        TLVF_LOG(ERROR) << "No call to create_previous_companies was called before add_previous_companies";
        return false;
    }
    uint8_t *src = (uint8_t *)m_previous_companies;
    if (m_previous_companies_idx__ > 0) {
        src = (uint8_t *)m_previous_companies_vector[m_previous_companies_idx__ - 1]->getBuffPtr();
    }
    if (ptr->getStartBuffPtr() != src) {
        TLVF_LOG(ERROR) << "Received entry pointer is different than expected (expecting the same pointer returned from add method)";
        return false;
    }
    if (ptr->getLen() > getBuffRemainingBytes(ptr->getStartBuffPtr())) {;
        TLVF_LOG(ERROR) << "Not enough available space on buffer";
        return false;
    }
    m_previous_companies_idx__++;
    if (!m_parse__) { (*m_prev_comp_list_len)++; }
    size_t len = ptr->getLen();
    m_previous_companies_vector.push_back(ptr);
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    m_lock_allocation__ = false;
    return true;
}

void cDevProfile::class_swap()
{
    m_work_exp->struct_swap();
    for (size_t i = 0; i < m_previous_companies_idx__; i++){
        std::get<1>(previous_companies(i)).class_swap();
    }
}

bool cDevProfile::finalize()
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

size_t cDevProfile::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // dev_name_len
    class_size += sizeof(sDevProfile); // work_exp
    class_size += sizeof(uint8_t); // age
    class_size += sizeof(uint8_t); // prev_comp_list_len
    return class_size;
}

bool cDevProfile::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_dev_name_len = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_dev_name_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_dev_name = reinterpret_cast<char*>(m_buff_ptr__);
    uint8_t dev_name_len = *m_dev_name_len;
    m_dev_name_idx__ = dev_name_len;
    if (!buffPtrIncrementSafe(sizeof(char) * (dev_name_len))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (dev_name_len) << ") Failed!";
        return false;
    }
    m_work_exp = reinterpret_cast<sDevProfile*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sDevProfile))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sDevProfile) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_work_exp->struct_init(); }
    m_age = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_prev_comp_list_len = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_prev_comp_list_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_previous_companies = reinterpret_cast<cCompanyName*>(m_buff_ptr__);
    uint8_t prev_comp_list_len = *m_prev_comp_list_len;
    m_previous_companies_idx__ = 0;
    for (size_t i = 0; i < prev_comp_list_len; i++) {
        auto previous_companies = create_previous_companies();
        if (!previous_companies) {
            TLVF_LOG(ERROR) << "create_previous_companies() failed";
            return false;
        }
        if (!add_previous_companies(previous_companies)) {
            TLVF_LOG(ERROR) << "add_previous_companies() failed";
            return false;
        }
        // swap back since previous_companies will be swapped as part of the whole class swap
        previous_companies->class_swap();
    }
    if (m_parse__) { class_swap(); }
    return true;
}

cCompanyName::cCompanyName(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
cCompanyName::cCompanyName(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
cCompanyName::~cCompanyName() {
}
uint8_t& cCompanyName::comp_name_len() {
    return (uint8_t&)(*m_comp_name_len);
}

std::string cCompanyName::comp_name_str() {
    char *comp_name_ = comp_name();
    if (!comp_name_) { return std::string(); }
    auto str = std::string(comp_name_, m_comp_name_idx__);
    auto pos = str.find_first_of('\0');
    if (pos != std::string::npos) {
        str.erase(pos);
    }
    return str;
}

char* cCompanyName::comp_name(size_t length) {
    if( (m_comp_name_idx__ == 0) || (m_comp_name_idx__ < length) ) {
        TLVF_LOG(ERROR) << "comp_name length is smaller than requested length";
        return nullptr;
    }
    return ((char*)m_comp_name);
}

bool cCompanyName::set_comp_name(const std::string& str) { return set_comp_name(str.c_str(), str.size()); }
bool cCompanyName::set_comp_name(const char str[], size_t size) {
    if (str == nullptr) {
        TLVF_LOG(WARNING) << "set_comp_name received a null pointer.";
        return false;
    }
    if (m_comp_name_idx__ != 0) {
        TLVF_LOG(ERROR) << "set_comp_name was already allocated!";
        return false;
    }
    if (!alloc_comp_name(size)) { return false; }
    std::copy(str, str + size, m_comp_name);
    return true;
}
bool cCompanyName::alloc_comp_name(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list comp_name, abort!";
        return false;
    }
    size_t len = sizeof(char) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_comp_name[*m_comp_name_len];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_comp_name_idx__ += count;
    *m_comp_name_len += count;
    if (!buffPtrIncrementSafe(len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << len << ") Failed!";
        return false;
    }
    return true;
}

void cCompanyName::class_swap()
{
}

bool cCompanyName::finalize()
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

size_t cCompanyName::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(uint8_t); // comp_name_len
    return class_size;
}

bool cCompanyName::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_comp_name_len = reinterpret_cast<uint8_t*>(m_buff_ptr__);
    if (!m_parse__) *m_comp_name_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }
    m_comp_name = reinterpret_cast<char*>(m_buff_ptr__);
    uint8_t comp_name_len = *m_comp_name_len;
    m_comp_name_idx__ = comp_name_len;
    if (!buffPtrIncrementSafe(sizeof(char) * (comp_name_len))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(char) * (comp_name_len) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


