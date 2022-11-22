#ifndef __USLM_MESSAGES_H
#define __USLM_MESSAGES_H

/**
 * Data structures describing the binary protocol to `stationsniffer`
 *
 */
enum class message_type_t : uint32_t {
    /**
     * @brief To register a station of interest (i.e. this process will begin monitoring and collect link metrics if that STA is seen.)
     *
     */
    MSG_REGISTER_STA = 0x01,
    /**
     * @brief Unregister a station. Stop collecting metrics for this station. Pre-collected metrics, if any, will be lost.
     *
     */
    MSG_UNREGISTER_STA = 0x02,
    /**
     * @brief Get the link metric statistics for a station.
     *
     */
    MSG_GET_STA_STATS = 0x04,
    /**
     * @brief Get the link metric statistics for this station, but with the RSSI being a weighted mean average with more recent measurement weighed more.
     *
     */
    MSG_GET_STA_WMI_STATS = 0x08,
};

enum class error_code_t : uint32_t {
    /**
     * @brief No error! Good to go.
     *
     *
     */
    ERROR_OK = 0x00,
    /**
     * @brief The station that was request to act upon is not known to this Agent.
     *
     */
    ERROR_STA_NOT_KNOWN = 0x01,
    /**
     * @brief Client fed us a malformed message.
     *
     */
    ERROR_BAD_MESSAGE = 0x02,
};

struct message_request_header {
    message_type_t message_type;
    uint8_t mac[6];
    uint32_t checksum;
} __attribute__((packed));

struct message_response_header {
    error_code_t error_code;
    // the MAC this response is about.
    uint8_t mac[6];
} __attribute__((packed));
struct request {
    message_request_header header;
} __attribute__((packed));

struct response {
    message_response_header response;
} __attribute__((packed));

struct sta_lm : public response {
    int8_t rssi;
    int16_t channel_number;
    uint64_t timestamp;
} __attribute__((packed));

struct sta_wma_lm : public response {
    int8_t rssi;
    int16_t channel_number;
    uint64_t timestamp;
    int8_t wma_rssi;
} __attribute__((packed));

struct periodicity_message : public request {
    uint32_t periodicity_ms;
} __attribute__((packed));


#endif // __USLM_MESSAGES_H
