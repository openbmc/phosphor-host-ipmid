#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <phosphor-logging/lg2.hpp>

namespace group
{
constexpr ipmi::Cmd cmdGetGroupExt = 0x0;
} // namespace group

void registerNetFnGroupExtFunctions() __attribute__((constructor));

ipmi::RspType<uint8_t> ipmiGroupExt()
{
    lg2::info("IPMI GROUP EXTENSIONS");

    // Generic return from IPMI commands.
    static uint8_t respData = 0;

    return ipmi::responseSuccess(respData);
}

void registerNetFnGroupExtFunctions()
{
    // <Group Extension Command>
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                               group::cmdGetGroupExt, ipmi::Privilege::User,
                               ipmiGroupExt);

    return;
}
