#include <bpl/bpl_service_prio_utils.h>
#include <list>
#include <memory>
#include <set>
#include <string>

namespace beerocks {
namespace bpl {

class ServicePrioritizationUtils_tc : public ServicePrioritizationUtils {
public:
    bool flush_rules() override;
    bool apply_single_value_map(std::list<struct sInterfaceTagInfo> *iface_list,
                                uint8_t pcp) override;
    bool apply_dscp_map(std::list<struct sInterfaceTagInfo> *iface_list, struct sDscpMap *map,
                        uint8_t default_pcp = 0) override;
    bool apply_up_map(std::list<struct sInterfaceTagInfo> *iface_list,
                      uint8_t default_pcp = 0) override;

private:
    std::set<std::string> m_applied_ifaces;
};

} // namespace bpl
} // namespace beerocks
