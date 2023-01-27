
#include <bcl/beerocks_defines.h>

#include <tlvf/ieee_1905_1/eMediaType.h>

#include <string>

#include "../agent_db.h"

namespace beerocks {

class MediaType {

public:
    /**
     * @brief Gets media type for the given radio.
     *
     * Media type value is obtained by checking the IEEE802.11 revisions supported.
     * Returns UNKNOWN_MEDIA if media type can't be determined.
     *
     * @param radio Reference on a radio object.
     * @return Media type value.
     */
    static ieee1905_1::eMediaType get_802_11_media_type(const beerocks::AgentDB::sRadio &radio);
    /**
     * @brief Gets media type for given interface.
     *
     * The mechanism to use to obtain media type depends on the media type group:
     * Ethernet, WiFi, MoCA, etc.
     *
     * @param[in] interface_name Name of the local interface.
     * @param[in] media_type_group The media type group of the connecting interface.
     * @param[in, out] media_type The underlying network technology of the connecting interface.
     *
     * @return True on success and false otherwise.
     */
    static bool get_media_type(const std::string &interface_name,
                               ieee1905_1::eMediaTypeGroup media_type_group,
                               ieee1905_1::eMediaType &media_type);
};

} // namespace beerocks
