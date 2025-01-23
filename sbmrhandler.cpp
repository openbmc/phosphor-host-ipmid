#include "sbmrhandler.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>

void register_netfn_sbmr_functions() __attribute__((constructor));
using SbmrBootProgressCode =
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>;

namespace ipmi
{

static const std::map<std::string, std::string> sbmrBootProgressStages{
    {"0x01000000050001c100", "PrimaryProcInit"},
    {"0x01000000060001c100", "SecondaryProcInit"},
    {"0x010000000110010200", "PCIInit"},
    {"0x010000000110040300", "SystemInitComplete"},
    {"0x010000000700050300", "SystemSetup"},
    {"0x010000000180050300", "OSStart"},
    {"0x010000001910100300", "OSRunning"}};

void updateBootProgressProperty(std::string prop)
{
    auto bus = getSdBus();
    try
    {
        std::string bootProgress =
            "xyz.openbmc_project.State.Boot.Progress.ProgressStages." + prop;
        ipmi::setDbusProperty(*bus, sbmrHostStateService, sbmrHostStateObj,
                              sbmrHostStateIntf, "BootProgress", bootProgress);
    }
    catch (const std::exception& e)
    {
        lg2::error("updateBootProgressProperty: can't set property");
    }
}

void updateBootProgressLastUpdateProperty(uint64_t timeStamp)
{
    auto bus = getSdBus();
    try
    {
        ipmi::setDbusProperty(*bus, sbmrHostStateService, sbmrHostStateObj,
                              sbmrHostStateIntf, "BootProgressLastUpdate",
                              timeStamp);
    }
    catch (const std::exception& e)
    {
        lg2::error("updateBootProgressLastUpdateProperty: can't set property");
    }
}

ipmi::RspType<uint8_t>
    sendBootProgressCode(ipmi::Context::ptr ctx, std::vector<uint8_t> data)
{
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info, channel={CHANNEL}", "CHANNEL",
                   ctx->channel);
        return ipmi::responseUnspecifiedError();
    }

    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20))
    {
        lg2::error("Error - supported only in SSIF interface");
        return ipmi::responseCommandNotAvailable();
    }

    if (data.size() != sbmrBootProgressCodeSize)
    {
        lg2::error("Error - Invalid boot progress length {LENGTH}", "LENGTH",
                   data.size());
        return ipmi::responseReqDataLenInvalid();
    }

    try
    {
        /* Update boot progress code to Dbus property */
        SbmrBootProgressCode bpCode(std::move(data), {});

        auto method = ctx->bus->new_method_call(
            sbmrBootStateService, sbmrBootStateObj, dbusPropertyIntf, "Set");
        method.append(sbmrBootStateIntf, "Value",
                      std::variant<SbmrBootProgressCode>(std::move(bpCode)));
        auto reply = ctx->bus->call(method);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to set boot progress code, Error={ERROR}", "ERROR",
                   e.what());
        return ipmi::responseUnspecifiedError();
    }

    /* Update Redfish BootProgress object */
    std::stringstream hexCode;
    hexCode << "0x" << std::hex << std::setfill('0');
    for (auto byte : data)
    {
        hexCode << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    auto timeStamp = std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    updateBootProgressLastUpdateProperty(timeStamp);

    /* Find the mapping for BootProgressTypes */
    auto found = sbmrBootProgressStages.find(hexCode.str());
    if (found == sbmrBootProgressStages.end())
    {
        updateBootProgressProperty(oemSbmrBootStage);
    }
    else
    {
        updateBootProgressProperty(found->second);
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<std::vector<uint8_t>> getBootProgressCode(ipmi::Context::ptr ctx)
{
    try
    {
        auto method = ctx->bus->new_method_call(
            sbmrBootStateService, sbmrBootStateObj, dbusPropertyIntf, "Get");
        method.append(sbmrBootStateIntf, "Value");

        auto reply = ctx->bus->call(method);
        if (reply.is_method_error())
        {
            lg2::error("Get Dbus method returned error");
            return ipmi::responseUnspecifiedError();
        }

        std::variant<SbmrBootProgressCode> variantValue;
        reply.read(variantValue);

        auto getRecord = std::get<SbmrBootProgressCode>(variantValue);
        auto respBootProgressCode = std::get<0>(getRecord);
        if (respBootProgressCode.empty() ||
            respBootProgressCode.size() != sbmrBootProgressCodeSize)
        {
            return ipmi::responseUnspecifiedError();
        }

        return ipmi::responseSuccess(respBootProgressCode);
    }
    catch (const std::exception& e)
    {
        lg2::error("Can't get property Value, Error={ERROR}", "ERROR",
                   e.what());
        return ipmi::responseUnspecifiedError();
    }
}

} // namespace ipmi

void register_netfn_sbmr_functions()
{
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupSBMR,
                         ipmi::sbmr::cmdSendBootProgressCode,
                         ipmi::Privilege::Admin, ipmi::sendBootProgressCode);

    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupSBMR,
                         ipmi::sbmr::cmdGetBootProgressCode,
                         ipmi::Privilege::User, ipmi::getBootProgressCode);
}
