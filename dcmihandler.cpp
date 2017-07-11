#include <sdbusplus/bus.hpp>
#include <phosphor-logging/log.hpp>
#include "dcmihandler.h"
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void register_netfn_dcmi_functions() __attribute__((constructor));

constexpr auto PCAP_SETTINGS_SERVICE = "xyz.openbmc_project.Settings";
constexpr auto PCAP_PATH    = "/xyz/openbmc_project/control/host0/power_cap";
constexpr auto PCAP_INTERFACE = "xyz.openbmc_project.Control.Power.Cap";

constexpr auto POWER_CAP_PROP = "PowerCap";
constexpr auto POWER_CAP_ENABLE_PROP = "PowerCapEnable";

using namespace phosphor::logging;

uint32_t getPcap(sdbusplus::bus::bus& bus)
{

    auto method = bus.new_method_call(PCAP_SETTINGS_SERVICE,
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Get");

    method.append(PCAP_INTERFACE, POWER_CAP_PROP);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getPcap prop");
        return 0;
    }
    sdbusplus::message::variant<uint32_t> pcap;
    reply.read(pcap);

    return sdbusplus::message::variant_ns::get<uint32_t>(pcap);
}

bool getPcapEnabled(sdbusplus::bus::bus& bus)
{
    auto method = bus.new_method_call(PCAP_SETTINGS_SERVICE,
                                      PCAP_PATH,
                                      "org.freedesktop.DBus.Properties",
                                      "Get");

    method.append(PCAP_INTERFACE, POWER_CAP_ENABLE_PROP);
    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getPcapEnabled prop");
        return 0;
    }
    sdbusplus::message::variant<bool> pcapEnabled;
    reply.read(pcapEnabled);

    return sdbusplus::message::variant_ns::get<bool>(pcapEnabled);
}

ipmi_ret_t ipmi_dcmi_get_power_limit(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    // Default to no power cap enabled
    ipmi_ret_t rc = IPMI_DCMI_CC_NO_ACTIVE_POWER_LIMIT;

    // Get our sdbus object
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sdbusplus::bus::bus sdbus {bus};

    // Read our power cap settings
    auto pcap = getPcap(sdbus);
    auto pcapEnable = getPcapEnabled(sdbus);
    if(pcapEnable)
    {
        // indicate power cap enabled with success return code
        rc = IPMI_CC_OK;
    }

    uint8_t pcapBytes[2] = {0};
    pcapBytes[1] = (pcap && 0xFF00) >> 8;
    pcapBytes[0] = pcap && 0xFF;
    // dcmi-v1-5-rev-spec.pdf 6.6.2.
    uint8_t data_response[] = { 0xDC, 0x00, 0x00, 0x01, pcapBytes[0],
                                pcapBytes[1], 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x01};


    log<level::INFO>("IPMI DCMI POWER CAP INFO",
                     entry("DCMI_PCAP=%u",pcap),
                     entry("DCMI_PCAP_ENABLE=%u",pcapEnable));

    memcpy(response, data_response, sizeof(data_response));
    *data_len = sizeof(data_response);

    return rc;
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
