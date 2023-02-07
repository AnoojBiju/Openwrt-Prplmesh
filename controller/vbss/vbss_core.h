//
//  Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//

#ifndef PRPLMESH_VBSS_CORE_H
#define PRPLMESH_VBSS_CORE_H
#include <map>
#include <set>
#include <vector>

#include "vbss_ds.h"

namespace vbss {

class VbssCore {

public:
    using vbss_id_set = std::set<vbss_id>;
    using vbss_id_map = std::map<ruid, vbss_id_set>;

    static constexpr uint8_t MAX_FLIPPED_BITS = 5;
    static constexpr uint8_t ZERO_MASK        = 0;
    static constexpr uint8_t BYTE_LEN         = 8;
    static constexpr uint8_t BEST_MOVE_COUNT  = 3;

    VbssCore();

    ~VbssCore();

    /**
     * @brief Create a set of vbss ids object
     *
     * @param mask The MAC Mask that the agent requires
     * @param fixed_bits The Fixed mac bits the Agent requires
     * @return true If the process was successful
     * @return false If an error has occurred
     */
    bool create_set_of_vbss_ids(const uint8_t bssid_orig[ETH_ALEN],
                                const uint8_t fixed_mask[ETH_ALEN],
                                const uint8_t fixed_bits[ETH_ALEN], const uint8_t &max_numbers,
                                std::vector<vbss_id> &vbss_id_list);

    /**
     * @brief Attempt to add a new station
     *
     * @param vsta_mac Mac address of station available
     * @return true
     * @return false
     */
    bool add_new_station(const uint8_t vsta_mac[ETH_ALEN]);

    bool compare_incoming_to_curr(const int8_t &cur_rssi, const int8_t &income_rssi);

protected:
    /**
     * Max number of vbss in the system
    */
    uint8_t m_max_num_vbss_system;
    /**
     * Current number of used vbss in system
    */
    uint8_t m_current_num_vbss;

    uint8_t copy_fixed_and_base(const uint8_t fixed[ETH_ALEN], const uint8_t base[ETH_ALEN],
                                vbss::vbss_id &tmp_bssid);

private:
    std::vector<uint8_t> determine_orthogonal_vals(const uint8_t &b_val);
};

} // namespace vbss

#endif //PRPLMESH_VBSS_CORE_H
