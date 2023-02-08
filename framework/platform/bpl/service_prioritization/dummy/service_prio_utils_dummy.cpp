#include "service_prio_utils_dummy.h"
#include <easylogging++.h>

namespace beerocks {
namespace bpl {

bool ServicePrioritizationUtils_dummy::flush_rules()
{
	LOG(ERROR) << "%s:not Supported in Dummy" << __func__ ;
	return false;
}

bool ServicePrioritizationUtils_dummy::apply_single_value_map(uint8_t pcp)
{
	LOG(ERROR) << "%s:not Supported in Dummy" << __func__ ;
	return false;
}

bool ServicePrioritizationUtils_dummy::apply_dscp_map()
{
	LOG(ERROR) << "%s:not Supported in Dummy" << __func__ ;
        return false;
}

bool ServicePrioritizationUtils_dummy::apply_up_map()
{
	LOG(ERROR) << "%s:not Supported in Dummy" << __func__ ;
        return false;
}


std::shared_ptr<ServicePrioritizationUtils> register_service_prio_utils()
{
    return std::make_shared<bpl::ServicePrioritizationUtils_dummy>();
}

}

}
