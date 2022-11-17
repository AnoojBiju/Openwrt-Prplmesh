/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef UNASSOCIATED_STATION_H
#define UNASSOCIATED_STATION_H

#include "agent.h"
#include <bcl/beerocks_defines.h>
#include <bcl/network/network_utils.h>

namespace prplmesh {
namespace controller {
namespace db {

// TODO : discuss if we better use the main Station class and append it ?? o splitting them into a base Station
// class and two children: associated/nonAssociated
// For this first version, I will use this new light class
class UnassociatedStation {
public:
    UnassociatedStation()                            = delete;
    UnassociatedStation(const UnassociatedStation &) = delete;
    explicit UnassociatedStation(const sMacAddr &al_mac_) : m_mac_address(al_mac_) {}

    struct Stats {
        uint8_t uplink_rcpi_dbm_enc = 0;
        std::string time_stamp;
    };

    void update_stats(const Stats &new_stats) { m_stats = new_stats; };
    const Stats get_stats() const { return m_stats; };
    void set_channel(uint channel_in) { m_channel = channel_in; };
    const sMacAddr &get_mac_Address() const { return m_mac_address; };
    uint get_channel() const { return m_channel; };

    /**
     * @brief set radio mac_addr monitoring the station
     *
     * @param agent_mac_addr agent mac_addr
     * @param radio_mac_addr 
     * @return true on success and false otherwise.
     */
    bool set_radio_mac(const sMacAddr &agent_mac_addr, const sMacAddr &radio_mac)
    {
        auto entry = m_agents.find(agent_mac_addr);
        if (entry != m_agents.end()) {
            m_agents[agent_mac_addr] = radio_mac;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @brief get radio mac_addr monitoring the station
     *
     * @param agent_mac_addr agent mac_addr
     * @param radio_mac_addr 
     * @return true if agent found, false otherwise.
     */
    bool get_radio_mac(const sMacAddr &agent_mac_addr, sMacAddr &radio_mac_addr) const
    {
        auto entry = m_agents.find(agent_mac_addr);
        if (entry != m_agents.end()) {
            radio_mac_addr = entry->second;
            return true;
        } else {
            return false;
        }
    }
    /**
     * @brief add agent to be monitoring the station
     *
     * @param agent_mac_addr agent mac_addr
     * @param radio_mac_addr 
     * @return true on success and false otherwise.
     */
    bool add_agent(const sMacAddr &agent_mac_addr, const sMacAddr &radio_mac = sMacAddr())
    {
        m_agents[agent_mac_addr] = radio_mac;
        return true;
    }

    /**
     * @brief set agent radio
     *
     * @param agent_mac_addr agent mac_addr
     * @param radio_mac_addr 
     * @return true when radio mac is updated .false when agent is not found
     */
    bool set_agent_radio(const sMacAddr &agent_mac_addr, const sMacAddr &radio_mac = sMacAddr())
    {
        if (m_agents.find(agent_mac_addr) != m_agents.end()) {
            m_agents[agent_mac_addr] = radio_mac;
            return true;
        } else {
            LOG(ERROR) << "agent with mac_addr: " << tlvf::mac_to_string(agent_mac_addr)
                       << " is not monitoring station with mac_addr: "
                       << tlvf::mac_to_string(m_mac_address);
            return false;
        }
    }

    /**
     * @brief get agents monitoring this specific station
     *
     * @return list of <mac_agent, mac_radio_inside_agent>
     */
    const std::unordered_map<sMacAddr, sMacAddr> &get_agents() const { return m_agents; };

private:
    sMacAddr m_mac_address;
    uint m_channel = 0;
    //map of all agents monitoring this unassociated station  , first element is sMacAddr of the agent, second element is the sMacAddr of tha radio
    std::unordered_map<sMacAddr, sMacAddr> m_agents;

    Stats m_stats;
};
} // namespace db
} // namespace controller
} // namespace prplmesh
#endif
