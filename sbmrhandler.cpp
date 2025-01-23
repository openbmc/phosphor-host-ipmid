#include "sbmrhandler.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>

void register_netfn_sbmr_functions() __attribute__((constructor));

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

void updateBootProgressProperty(ipmi::Context::ptr& ctx,
                                const std::string& prop)
{
    std::string bootProgress =
        "xyz.openbmc_project.State.Boot.Progress.ProgressStages." + prop;
    boost::system::error_code ec =
        ipmi::setDbusProperty(ctx, sbmrHostStateService, sbmrHostStateObj,
                              sbmrHostStateIntf, "BootProgress", bootProgress);
    if (ec.value())
    {
        lg2::error(
            "updateBootProgressProperty, can't set progerty - Error={ERROR}",
            "ERROR", ec.what());
        return;
    }
}

void updateBootProgressLastUpdateProperty(ipmi::Context::ptr& ctx,
                                          uint64_t timeStamp)
{
    boost::system::error_code ec = ipmi::setDbusProperty(
        ctx, sbmrHostStateService, sbmrHostStateObj, sbmrHostStateIntf,
        "BootProgressLastUpdate", timeStamp);
    if (ec.value())
    {
        lg2::error(
            "updateBootProgressLastUpdateProperty, can't set property - Error={ERROR}",
            "ERROR", ec.what());
        return;
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

    /* Update boot progress code to Dbus property */
    SbmrBootProgressCode bpCode(std::move(data), {});
    boost::system::error_code ec =
        setDbusProperty(ctx, sbmrBootStateService, sbmrBootStateObj,
                        sbmrBootStateIntf, "Value", bpCode);

    if (ec.value())
    {
        lg2::error("Failed to set boot progress code, Error={ERROR}", "ERROR",
                   ec.message());
        return ipmi::responseUnspecifiedError();
    }

    /* Update Redfish BootProgress object */
    auto timeStamp = std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    updateBootProgressLastUpdateProperty(ctx, timeStamp);

    /* Find the mapping for BootProgressTypes */
    std::string hexCode = bytesToHexString(data);
    auto found = sbmrBootProgressStages.find(hexCode);
    if (found == sbmrBootProgressStages.end())
    {
        updateBootProgressProperty(ctx, oemSbmrBootStage);
    }
    else
    {
        updateBootProgressProperty(ctx, found->second);
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<std::vector<uint8_t>> getBootProgressCode(ipmi::Context::ptr ctx)
{
    SbmrBootProgressCode value;
    boost::system::error_code ec =
        getDbusProperty(ctx, sbmrBootStateService, sbmrBootStateObj,
                        sbmrBootStateIntf, "Value", value);
    if (ec.value())
    {
        lg2::error("Can't get property Value, Error={ERROR}", "ERROR",
                   ec.what());
        return ipmi::responseUnspecifiedError();
    }

    auto respBootProgressCode = std::get<0>(std::move(value));
    if (respBootProgressCode.size() != sbmrBootProgressCodeSize)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(respBootProgressCode);
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
