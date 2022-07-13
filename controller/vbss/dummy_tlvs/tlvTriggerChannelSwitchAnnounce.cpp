#include "tlvTriggerChannelSwitchAnnounce.h"

tlvTriggerChannelSwitchAnnounce::tlvTriggerChannelSwitchAnnounce(uint8_t *buff, size_t buff_len,
                                                                 bool parse = false)
    : BaseClass(buff, buff_len, parse)
{
    m_init_succeeded = init();
}

tlvTriggerChannelSwitchAnnounce::~tlvTriggerChannelSwitchAnnounce() {}

size_t tlvTriggerChannelSwitchAnnounce::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(wfa_map::eTlvTypeMap); // type
    class_size += sizeof(uint16_t);             // length
    class_size += sizeof(uint16_t);             // subtype

    class_size += sizeof(uint8_t); // csa_channel
    class_size += sizeof(uint8_t); // op_class

    return class_size;
}

bool tlvTriggerChannelSwitchAnnounce::init()
{
    if (getBuffRemainingBytes() < get_initial_size()) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    // Parse Type
    m_type = reinterpret_cast<wfa_map::eTlvTypeMap *>(m_buff_ptr__);
    if (!m_parse__)
        *((uint8_t *)m_type) = 0xDE; //TODO: This is just the current type
    if (!buffPtrIncrementSafe(sizeof(wfa_map::eTlvTypeMap))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(wfa_map::eTlvTypeMap)
                   << ") Failed!";
        return false;
    }
    // Parse Length
    m_length = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }
    // Parse Subtype
    m_subtype = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_subtype = 0x0006;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse CSA Channel
    m_csa_channel = reinterpret_cast<uint8_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_csa_channel = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }

    // Parse Op Class
    m_op_class = reinterpret_cast<uint8_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_op_class = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint8_t) << ") Failed!";
        return false;
    }

    if (m_parse__) {
        class_swap();
    }
    if (m_parse__) {
        if ((uint8_t)*m_type != 0xDE) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(0xDE)
                            << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}
