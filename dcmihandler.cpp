#include "dcmihandler.h"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/elog-errors.hpp>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "utils.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

using namespace phosphor::logging;
using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void register_netfn_dcmi_functions() __attribute__((constructor));


ipmi_ret_t ipmi_dcmi_get_power_limit(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_DCMI_CC_NO_ACTIVE_POWER_LIMIT;

    // dcmi-v1-5-rev-spec.pdf 6.6.2.   
    // This is good enough for OpenBMC support for OpenPOWER based systems
    // TODO research if more is needed
    uint8_t data_response[] = { 0xDC, 0x00, 0x00, 0x01, 0x00, 0x00, 
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                0x00, 0x01};



    printf("IPMI DCMI_GET_POWER_LEVEL\n");

    memcpy(response, data_response, sizeof(data_response));
    *data_len = sizeof(data_response);

    return rc;
}

/** @brief Read the asset tag of the server
 *
 *  @return On success return the asset tag and throw exception in case of
 *          error.
 */
std::string readAssetTag()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus,
                                    dcmi::assetTagIntf,
                                    dcmi::assetTagPath);

    auto method = bus.new_method_call(service.c_str(),
                                      dcmi::assetTagPath,
                                      dcmi::propIntf,
                                      "Get");
    method.append(dcmi::assetTagIntf);
    method.append(dcmi::assetTagProp);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading asset tag");
        elog<InternalFailure>();
    }

    sdbusplus::message::variant<std::string> assetTag;
    reply.read(assetTag);

    return sdbusplus::message::variant_ns::get<std::string>(assetTag);
}

void register_netfn_dcmi_functions()
{
    // <Get Power Limit>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER);
    ipmi_register_callback(NETFUN_GRPEXT, IPMI_CMD_DCMI_GET_POWER, NULL, ipmi_dcmi_get_power_limit,
                           PRIVILEGE_USER);
    return;
}
// 956379
