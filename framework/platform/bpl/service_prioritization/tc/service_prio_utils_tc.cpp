#include "service_prio_utils_tc.h"
#include <bcl/beerocks_event_loop_impl.h>
#include <bcl/beerocks_os_utils.h>
#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <easylogging++.h>

namespace beerocks {
namespace bpl {

namespace {
const std::string INGRESS_QDISC = "ingress";
const std::string ROOT_QDISC    = "root";

void setup_ingress_qdisc(const std::string &iface_name)
{
    LOG(DEBUG) << "Setting up ingress qdisc for " << iface_name;
    auto cmd = "tc qdisc add dev " + iface_name + " handle ffff: " + INGRESS_QDISC;
    beerocks::os_utils::system_call(cmd);
}

void setup_root_qdisc(const std::string &iface_name)
{
    LOG(DEBUG) << "Setting up root qdisc for " << iface_name;
    auto cmd =
        "tc qdisc add dev " + iface_name + " " + ROOT_QDISC + " root handle 1: htb default 10";
    beerocks::os_utils::system_call(cmd);
}

void create_htb_classes(const std::string &iface_name)
{
    LOG(DEBUG) << "Creating HTB classes for " << iface_name;
    auto cmd = "tc class add dev " + iface_name + " parent 1: classid 1:1 htb rate 100mbit";
    beerocks::os_utils::system_call(cmd);
    cmd = "tc class add dev " + iface_name + " parent 1:1 classid 1:10 htb rate 50mbit";
    beerocks::os_utils::system_call(cmd);
}

void set_priority_for_vlan_tagged_packets(const std::string &iface_name)
{
    LOG(DEBUG) << "Setting priority for VLAN tagged packets on " << iface_name;
    auto cmd = "tc filter add dev " + iface_name +
               " parent ffff: protocol 802.1Q u32 match u8 0 0 action skbedit priority 0";
    beerocks::os_utils::system_call(cmd);
    cmd = "tc filter add dev " + iface_name +
          " parent 1: protocol 802.1Q u32 match u8 0 0 action skbedit priority 0";
    beerocks::os_utils::system_call(cmd);
}

void set_priority_for_untagged_packets(const std::string &iface_name, uint8_t default_pcp)
{
    LOG(DEBUG) << "Setting priority for all packets and DSCP for IPv4 packets on " << iface_name;
    auto cmd = "tc filter add dev " + iface_name +
               " parent ffff: protocol all u32 match u8 0 0 action skbedit priority " +
               std::to_string(default_pcp);
    beerocks::os_utils::system_call(cmd);
    cmd = "tc filter add dev " + iface_name +
          " parent ffff: protocol ip u32 match ip protocol 0 0xff action skbedit priority " +
          std::to_string(default_pcp);
    beerocks::os_utils::system_call(cmd);
}

void apply_all_rules(const std::string &iface_name, ServicePrioritizationUtils::ePortMode tag_mode,
                     uint8_t default_pcp)
{
    setup_ingress_qdisc(iface_name);
    setup_root_qdisc(iface_name);
    create_htb_classes(iface_name);
    if (tag_mode == ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_TAGGED) {
        set_priority_for_vlan_tagged_packets(iface_name);
    } else if (tag_mode == ServicePrioritizationUtils::ePortMode::TAGGED_PORT_PRIMARY_UNTAGGED ||
               tag_mode == ServicePrioritizationUtils::ePortMode::UNTAGGED_PORT) {
        set_priority_for_untagged_packets(iface_name, default_pcp);
    }
}

void remove_tc_rules(const std::string &iface_name)
{
    LOG(DEBUG) << "Removing all tc rules for " + iface_name;
    auto cmd = "tc qdisc del dev " + iface_name + " root";
    beerocks::os_utils::system_call(cmd);
    cmd = "tc qdisc del dev " + iface_name + " ingress";
    beerocks::os_utils::system_call(cmd);
}

} // namespace

bool ServicePrioritizationUtils_tc::flush_rules()
{
    LOG(DEBUG) << "Flushing tc rules";

    for (const auto &iface_name : m_applied_ifaces) {
        remove_tc_rules(iface_name);
    }

    m_applied_ifaces.clear();
    return true;
}

bool ServicePrioritizationUtils_tc::apply_single_value_map(
    std::list<struct sInterfaceTagInfo> *iface_list, uint8_t pcp)
{
    LOG(DEBUG) << "Applying single value map using tc";

    for (const auto &iface : *iface_list) {
        apply_all_rules(iface.iface_name, iface.tag_info, pcp);
        m_applied_ifaces.insert(iface.iface_name);
    }

    return true;
}

bool ServicePrioritizationUtils_tc::apply_dscp_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                                   struct sDscpMap *map, uint8_t default_pcp)
{
    LOG(DEBUG) << "Applying DSCP map using tc | Just applying default_pcp";

    for (const auto &iface : *iface_list) {
        apply_all_rules(iface.iface_name, iface.tag_info, default_pcp);
        m_applied_ifaces.insert(iface.iface_name);
    }

    return true;
}

bool ServicePrioritizationUtils_tc::apply_up_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                                 uint8_t default_pcp)
{
    LOG(DEBUG) << "Applying UP map using tc | Just applying default_pcp";

    for (const auto &iface : *iface_list) {
        apply_all_rules(iface.iface_name, iface.tag_info, default_pcp);
        m_applied_ifaces.insert(iface.iface_name);
    }

    return true;
}

std::shared_ptr<ServicePrioritizationUtils> register_service_prio_utils()
{
    return std::make_shared<ServicePrioritizationUtils_tc>();
}

} // namespace bpl
} // namespace beerocks
