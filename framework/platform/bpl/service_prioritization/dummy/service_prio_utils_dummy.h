#include <bpl/bpl_service_prio_utils.h>

namespace beerocks {
namespace bpl {

class ServicePrioritizationUtils_dummy : public ServicePrioritizationUtils {
    virtual bool flush_rules() override;
    virtual bool apply_single_value_map(uint8_t pcp) override;
    virtual bool apply_dscp_map() override;
    virtual bool apply_up_map() override;

};

}
}
