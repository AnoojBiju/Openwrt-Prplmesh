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
const std::string PRIO_QDISC    = "prio";

void apply_tc_rules(const std::string &iface_name, uint8_t default_pcp)
{
    LOG(DEBUG) << "Apply tc rules for " << iface_name;

    // Setup ingress qdisc
    auto cmd = "tc qdisc add dev " + iface_name + " handle ffff: " + INGRESS_QDISC;
    beerocks::os_utils::system_call(cmd);

    // Setup prio qdisc
    cmd = "tc qdisc add dev " + iface_name + " root handle 1: " + PRIO_QDISC;
    beerocks::os_utils::system_call(cmd);

    // Setup filtering rules for tagged traffic
    cmd = "tc filter add dev " + iface_name +
          " protocol 802.1Q parent ffff: prio 1 u32 match u16 0x8100 0xffff at -2 "
          "action pedit pedit munge ethertype set 0x8100 pipe munge u16 set " +
          std::to_string(default_pcp) + " at 0 ";
    beerocks::os_utils::system_call(cmd);

    // Setup filtering rules for untagged traffic
    cmd = "tc filter add dev " + iface_name +
          " protocol ip parent ffff: prio 2 u32 match ip protocol 0 0x00 "
          "action pedit pedit munge ip dscp set " +
          std::to_string(default_pcp);
    beerocks::os_utils::system_call(cmd);
}

void remove_tc_rules(const std::string &iface_name)
{
    LOG(DEBUG) << "Remove tc rules for " << iface_name;

    // Remove ingress qdisc
    auto cmd = "tc qdisc del dev " + iface_name + " ingress";
    beerocks::os_utils::system_call(cmd);

    // Remove root qdisc
    cmd = "tc qdisc del dev " + iface_name + " root";
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
        apply_tc_rules(iface.iface_name, pcp);
        m_applied_ifaces.insert(iface.iface_name);
    }

    return true;
}

bool ServicePrioritizationUtils_tc::apply_dscp_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                                   struct sDscpMap *map, uint8_t default_pcp)
{
    LOG(DEBUG) << "Applying DSCP map using tc | Just applying default_pcp";

    for (const auto &iface : *iface_list) {
        apply_tc_rules(iface.iface_name, default_pcp);
        m_applied_ifaces.insert(iface.iface_name);
    }

    return true;
}

bool ServicePrioritizationUtils_tc::apply_up_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                                 uint8_t default_pcp)
{
    LOG(DEBUG) << "Applying UP map using tc | Just applying default_pcp";

    for (const auto &iface : *iface_list) {
        apply_tc_rules(iface.iface_name, default_pcp);
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
