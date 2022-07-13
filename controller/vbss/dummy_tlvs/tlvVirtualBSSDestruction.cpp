#include "tlvVirtualBSSDestruction.h"

tlvVirtualBSSDestruction::tlvVirtualBSSDestruction(uint8_t *buff, size_t buff_len,
                                                   bool parse = false)
    : BaseClass(buff, buff_len, parse)
{
    m_init_succeeded = init();
}

tlvVirtualBSSDestruction::~tlvVirtualBSSDestruction() {}

size_t tlvVirtualBSSDestruction::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(wfa_map::eTlvTypeMap); // type
    class_size += sizeof(uint16_t);             // length
    class_size += sizeof(uint16_t);             // subtype

    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(_Bool);    // should_disassociate_client

    return class_size;
}

bool tlvVirtualBSSDestruction::init()
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
        *m_subtype = 0x0003;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse RUID
    m_ruid = reinterpret_cast<sMacAddr *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(sMacAddr);
    }
    if (!m_parse__) {
        m_ruid->struct_init();
    }

    // Parse BSSID
    m_bssid = reinterpret_cast<sMacAddr *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(sMacAddr);
    }
    if (!m_parse__) {
        m_bssid->struct_init();
    }

    // Parse Should Disassociate
    m_disassociate_client = reinterpret_cast<uint8_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_disassociate_client = 0;
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
