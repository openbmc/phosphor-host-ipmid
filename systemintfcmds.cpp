#include "config.h"

#include "systemintfcmds.hpp"

#include "host-cmd-manager.hpp"
#include "host-interface.hpp"

#include <ipmid-host/cmd.hpp>
#include <ipmid/api.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <fstream>

void register_netfn_app_functions() __attribute__((constructor));

using namespace sdbusplus::server::xyz::openbmc_project::control;

// For accessing Host command manager
using cmdManagerPtr = std::unique_ptr<phosphor::host::command::Manager>;
extern cmdManagerPtr& ipmid_get_host_cmd_manager();

//-------------------------------------------------------------------
// Called by Host post response from Get_Message_Flags
//-------------------------------------------------------------------
ipmi::RspType<uint16_t,              // id
              uint8_t,               // type
              uint24_t,              //  manuf_id
              uint32_t,              // timestamp
              uint8_t,               // netfun
              uint8_t,               // cmd
              std::array<uint8_t, 4> // data
              >
    ipmiAppReadEventBuffer(ipmi::Context::ptr& ctx)
{
    // require this to be limited to system interface
    if (ctx->channel != ipmi::channelSystemIface)
    {
        return ipmi::responseInvalidCommand();
    }

    constexpr uint16_t selOemId = 0x5555;
    constexpr uint8_t selRecordTypeOem = 0xc0;

    // read manufacturer ID from dev_id file
    static uint24_t manufId{};
    if (!manufId)
    {
        const char* filename = "/usr/share/ipmi-providers/dev_id.json";
        std::ifstream devIdFile(filename);
        if (devIdFile.is_open())
        {
            auto data = nlohmann::json::parse(devIdFile, nullptr, false);
            if (!data.is_discarded())
            {
                manufId = data.value("manuf_id", 0);
            }
        }
    }

    constexpr uint32_t timestamp{0};

    // per IPMI spec NetFuntion for OEM
    constexpr uint8_t netfun = 0x3a;

    // Read from the Command Manager queue. What gets returned is a
    // pair of <command, data> that can be directly used here
    const auto& [cmd, data0] = ipmid_get_host_cmd_manager()->getNextCommand();
    constexpr uint8_t dataUnused = 0xff;

    return ipmi::responseSuccess(
        selOemId, selRecordTypeOem, manufId, timestamp, netfun, cmd,
        std::to_array<uint8_t>({data0, dataUnused, dataUnused, dataUnused}));
}

//---------------------------------------------------------------------
// Called by Host on seeing a SMS_ATN bit set. Return a hardcoded
// value of 0x0 to indicate Event Message Buffer is not supported
//-------------------------------------------------------------------
ipmi::RspType<uint8_t> ipmiAppGetMessageFlags()
{
    // From IPMI spec V2.0 for Get Message Flags Command :
    // bit:[1] from LSB : 1b = Event Message Buffer Full.
    // Return as 0 if Event Message Buffer is not supported,
    // or when the Event Message buffer is disabled.
    // This path is used to communicate messages to the host
    // from within the phosphor::host::command::Manager
    constexpr uint8_t setEventMsgBufferNotSupported = 0x0;
    return ipmi::responseSuccess(setEventMsgBufferNotSupported);
}

ipmi::RspType<bool,    // Receive Message Queue Interrupt Enabled
              bool,    // Event Message Buffer Full Interrupt Enabled
              bool,    // Event Message Buffer Enabled
              bool,    // System Event Logging Enabled
              uint1_t, // Reserved
              bool,    // OEM 0 enabled
              bool,    // OEM 1 enabled
              bool     // OEM 2 enabled
              >
    ipmiAppGetBMCGlobalEnable()
{
    return ipmi::responseSuccess(true, false, false, true, 0, false, false,
                                 false);
}

ipmi::RspType<> ipmiAppSetBMCGlobalEnable(
    ipmi::Context::ptr ctx, bool receiveMessageQueueInterruptEnabled,
    bool eventMessageBufferFullInterruptEnabled, bool eventMessageBufferEnabled,
    bool systemEventLogEnable, uint1_t reserved, bool OEM0Enabled,
    bool OEM1Enabled, bool OEM2Enabled)
{
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info, channel={CHANNEL}", "CHANNEL",
                   ctx->channel);
        return ipmi::responseUnspecifiedError();
    }

    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface))
    {
        lg2::error("Error - supported only in system interface");
        return ipmi::responseCommandNotAvailable();
    }

    // Recv Message Queue and SEL are enabled by default.
    // Event Message buffer are disabled by default (not supported).
    // Any request that try to change the mask will be rejected
    if (!receiveMessageQueueInterruptEnabled || !systemEventLogEnable ||
        eventMessageBufferFullInterruptEnabled || eventMessageBufferEnabled ||
        OEM0Enabled || OEM1Enabled || OEM2Enabled || reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    return ipmi::responseSuccess();
}

namespace
{
// Static storage to keep the object alive during process life
std::unique_ptr<phosphor::host::command::Host> host
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::server::manager_t> objManager
    __attribute__((init_priority(101)));
} // namespace

void register_netfn_app_functions()
{
    // <Read Event Message Buffer>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdReadEventMessageBuffer,
                          ipmi::Privilege::Admin, ipmiAppReadEventBuffer);

    // <Set BMC Global Enables>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdSetBmcGlobalEnables,
                          ipmi::Privilege::Admin, ipmiAppSetBMCGlobalEnable);

    // <Get BMC Global Enables>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetBmcGlobalEnables,
                          ipmi::Privilege::User, ipmiAppGetBMCGlobalEnable);

    // <Get Message Flags>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessageFlags, ipmi::Privilege::Admin,
                          ipmiAppGetMessageFlags);

    // Create new xyz.openbmc_project.host object on the bus
    auto objPath = std::string{CONTROL_HOST_OBJ_MGR} + '/' + HOST_NAME + '0';

    std::unique_ptr<sdbusplus::asio::connection>& sdbusp =
        ipmid_get_sdbus_plus_handler();

    // Add sdbusplus ObjectManager.
    objManager = std::make_unique<sdbusplus::server::manager_t>(
        *sdbusp, CONTROL_HOST_OBJ_MGR);

    host = std::make_unique<phosphor::host::command::Host>(
        *sdbusp, objPath.c_str());
    sdbusp->request_name(CONTROL_HOST_BUSNAME);

    return;
}
