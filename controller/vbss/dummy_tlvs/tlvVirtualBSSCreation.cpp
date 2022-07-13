#include "tlvVirtualBSSCreation.h"

tlvVirtualBSSCreation::tlvVirtualBSSCreation(uint8_t *buff, size_t buff_len, bool parse = false)
    : BaseClass(buff, buff_len, parse)
{
    m_init_succeeded = init();
}

tlvVirtualBSSCreation::~tlvVirtualBSSCreation() {}

size_t tlvVirtualBSSCreation::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(wfa_map::eTlvTypeMap); // type
    class_size += sizeof(uint16_t);             // length
    class_size += sizeof(uint16_t);             // subtype

    class_size += sizeof(sMacAddr); // ruid
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(uint16_t); // ssid_len
    class_size += sizeof(uint16_t); // pass_len
    class_size += sizeof(uint16_t); // dpp_conn_len
    class_size += sizeof(sMacAddr); // client_mac
    class_size += sizeof(_Bool);    // client_is_assoc
    class_size += sizeof(uint16_t); // key_len
    class_size += sizeof(uint64_t); // tx_packet_num
    class_size += sizeof(uint16_t); // group_key_len
    class_size += sizeof(uint64_t); // group_tx_packet_num

    return class_size;
}

bool tlvVirtualBSSCreation::init()
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
        *m_subtype = 0x0002;
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

    // Parse SSID Length
    m_ssid_len = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_ssid_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse SSID
    m_ssid = reinterpret_cast<char *>(m_buff_ptr__);
    if (!m_parse__)
        *m_ssid = 0;
    if (!buffPtrIncrementSafe(*m_ssid_len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << *m_ssid_len << ") Failed!";
        return false;
    }

    // Parse Pass Length
    m_pass_len = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_pass_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse Password
    m_password = reinterpret_cast<char *>(m_buff_ptr__);
    if (!m_parse__)
        *m_password = 0;
    if (!buffPtrIncrementSafe(*m_pass_len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << *m_pass_len << ") Failed!";
        return false;
    }

    // Parse DPP Connector Length
    m_dpp_conn_len = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_dpp_conn_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse DPP Connector
    m_dpp_conn = reinterpret_cast<char *>(m_buff_ptr__);
    if (!m_parse__)
        *m_dpp_conn = 0;
    if (!buffPtrIncrementSafe(*m_dpp_conn_len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << *m_dpp_conn_len << ") Failed!";
        return false;
    }

    // Parse Client MAC Address
    m_client_mac = reinterpret_cast<sMacAddr *>(m_buff_ptr__);
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(sMacAddr) << ") Failed!";
        return false;
    }
    if (m_length && !m_parse__) {
        (*m_length) += sizeof(sMacAddr);
    }
    if (!m_parse__) {
        m_client_mac->struct_init();
    }

    // Parse Client is Associated
    m_client_is_assoc = reinterpret_cast<_Bool *>(m_buff_ptr__);
    if (!m_parse__)
        *m_client_is_assoc = false;

    if (!buffPtrIncrementSafe(sizeof(_Bool))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(_Bool) << ") Failed!";
        return false;
    }

    // Parse Security Context members, all fields below are filled with 0s by default since m_client_assoc = false by default

    // Parse Key Length
    m_key_len = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_key_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse Pairwise Temporal Key
    m_ptk = reinterpret_cast<char *>(m_buff_ptr__);
    if (!m_parse__)
        *m_ptk = 0;
    if (!buffPtrIncrementSafe(*m_key_len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << *m_key_len << ") Failed!";
        return false;
    }

    // Parse Tx Packet Number
    m_tx_packet_num = reinterpret_cast<uint64_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_tx_packet_num = 0;
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
        return false;
    }

    // Parse Group Key Length
    m_group_key_len = reinterpret_cast<uint16_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_group_key_len = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint16_t) << ") Failed!";
        return false;
    }

    // Parse Group Temporal Key
    m_gtk = reinterpret_cast<char *>(m_buff_ptr__);
    if (!m_parse__)
        *m_gtk = 0;
    if (!buffPtrIncrementSafe(*m_group_key_len)) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << *m_group_key_len << ") Failed!";
        return false;
    }

    // Parse Group Tx Packet Number
    m_group_tx_packet_num = reinterpret_cast<uint64_t *>(m_buff_ptr__);
    if (!m_parse__)
        *m_group_tx_packet_num = 0;
    if (!buffPtrIncrementSafe(sizeof(uint64_t))) {
        LOG(ERROR) << "buffPtrIncrementSafe(" << std::dec << sizeof(uint64_t) << ") Failed!";
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
