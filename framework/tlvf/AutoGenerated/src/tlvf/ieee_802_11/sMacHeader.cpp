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

#include <tlvf/ieee_802_11/sMacHeader.h>
#include <tlvf/tlvflogging.h>

using namespace ieee802_11;

sMacHeader::sMacHeader(uint8_t* buff, size_t buff_len, bool parse) :
    BaseClass(buff, buff_len, parse) {
    m_init_succeeded = init();
}
sMacHeader::sMacHeader(std::shared_ptr<BaseClass> base, bool parse) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse){
    m_init_succeeded = init();
}
sMacHeader::~sMacHeader() {
}
sMacHeader::sFrameControlB1& sMacHeader::frame_control_b1() {
    return (sFrameControlB1&)(*m_frame_control_b1);
}

sMacHeader::sFrameControlB2& sMacHeader::frame_control_b2() {
    return (sFrameControlB2&)(*m_frame_control_b2);
}

uint16_t& sMacHeader::duration_id() {
    return (uint16_t&)(*m_duration_id);
}

sMacAddr& sMacHeader::addr1() {
    return (sMacAddr&)(*m_addr1);
}

sMacAddr& sMacHeader::addr2() {
    return (sMacAddr&)(*m_addr2);
}

sMacAddr& sMacHeader::addr3() {
    return (sMacAddr&)(*m_addr3);
}

uint16_t& sMacHeader::seq_ctrl() {
    return (uint16_t&)(*m_seq_ctrl);
}

void sMacHeader::class_swap()
{
    m_frame_control_b1->struct_swap();
    m_frame_control_b2->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_duration_id));
    m_addr1->struct_swap();
    m_addr2->struct_swap();
    m_addr3->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_seq_ctrl));
}

bool sMacHeader::finalize()
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

size_t sMacHeader::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sFrameControlB1); // frame_control_b1
    class_size += sizeof(sFrameControlB2); // frame_control_b2
    class_size += sizeof(uint16_t); // duration_id
    class_size += sizeof(sMacAddr); // addr1
    class_size += sizeof(sMacAddr); // addr2
    class_size += sizeof(sMacAddr); // addr3
    class_size += sizeof(uint16_t); // seq_ctrl
    return class_size;
}

bool sMacHeader::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_frame_control_b1 = reinterpret_cast<sFrameControlB1*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFrameControlB1))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFrameControlB1) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_frame_control_b1->struct_init(); }
    m_frame_control_b2 = reinterpret_cast<sFrameControlB2*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sFrameControlB2))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sFrameControlB2) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_frame_control_b2->struct_init(); }
    m_duration_id = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    m_addr1 = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_addr1->struct_init(); }
    m_addr2 = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_addr2->struct_init(); }
    m_addr3 = reinterpret_cast<sMacAddr*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (!m_parse__) { m_addr3->struct_init(); }
    m_seq_ctrl = reinterpret_cast<uint16_t*>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    if (m_parse__) { class_swap(); }
    return true;
}


