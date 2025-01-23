#include <ipmid/api.hpp>
#include <ipmid/filter.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>

constexpr auto sbmrBootStateIntf = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrHostStateIntf = "xyz.openbmc_project.State.Boot.Progress";
constexpr auto sbmrBootProgressCodeSize = 9;
constexpr auto oemSbmrBootStage = "OEM";

void registerNetfnSBMRFunctions() __attribute__((constructor));

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

bool updateBootProgressProperty(ipmi::Context::ptr& ctx,
                                const std::string& value)
{
    std::string bootProgress =
        "xyz.openbmc_project.State.Boot.Progress.ProgressStages." + value;
    ipmi::DbusObjectInfo sbmrHostStateObject{};

    /* Get Host State Object */
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, sbmrHostStateIntf, sbmrHostStateObject);
    if (ec.value())
    {
        lg2::error("Failed to get Host State object, Error={ERROR}", "ERROR",
                   ec.message());
        return false;
    }

    /* Set Host State property */
    ec = ipmi::setDbusProperty(ctx, sbmrHostStateObject.second,
                               sbmrHostStateObject.first, sbmrHostStateIntf,
                               "BootProgress", bootProgress);
    if (ec.value())
    {
        lg2::error(
            "updateBootProgressProperty, can't set progerty - Error={ERROR}",
            "ERROR", ec.what());
        return false;
    }

    return true;
}

bool updateBootProgressLastUpdateProperty(ipmi::Context::ptr& ctx,
                                          uint64_t timeStamp)
{
    ipmi::DbusObjectInfo sbmrHostStateObject{};

    /* Get Host State Object */
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, sbmrHostStateIntf, sbmrHostStateObject);
    if (ec.value())
    {
        lg2::error("Failed to get Host State object, Error={ERROR}", "ERROR",
                   ec.message());
        return false;
    }

    /* Set Host State property */
    ec = ipmi::setDbusProperty(ctx, sbmrHostStateObject.second,
                               sbmrHostStateObject.first, sbmrHostStateIntf,
                               "BootProgressLastUpdate", timeStamp);
    if (ec.value())
    {
        lg2::error(
            "updateBootProgressLastUpdateProperty, can't set property - Error={ERROR}",
            "ERROR", ec.what());
        return false;
    }

    return true;
}

ipmi::RspType<uint8_t> sendBootProgressCode(
    ipmi::Context::ptr ctx, std::array<uint8_t, sbmrBootProgressCodeSize>& data)
{
    /* Update boot progress code to Dbus property */
    BootProgressCode bpCode(std::vector(data.begin(), data.end()), {});
    ipmi::DbusObjectInfo sbmrBootStateObject{};

    /* Get Boot State Object */
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, sbmrBootStateIntf, sbmrBootStateObject);
    if (ec.value())
    {
        lg2::error("Failed to get Boot State object, Error={ERROR}", "ERROR",
                   ec.message());
        return ipmi::responseUnspecifiedError();
    }

    /* Set Boot State property */
    ec = ipmi::setDbusProperty(ctx, sbmrBootStateObject.second,
                               sbmrBootStateObject.first, sbmrBootStateIntf,
                               "Value", bpCode);
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
    if (!updateBootProgressLastUpdateProperty(ctx, timeStamp))
    {
        return ipmi::responseUnspecifiedError();
    }

    /* Find the mapping for BootProgressTypes */
    std::string hexCode = bytesToHexString(data);
    auto found = sbmrBootProgressStages.find(hexCode);

    auto stage = (found != sbmrBootProgressStages.end()) ? found->second
                                                         : oemSbmrBootStage;
    if (!updateBootProgressProperty(ctx, stage))
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<std::vector<uint8_t>> getBootProgressCode(ipmi::Context::ptr ctx)
{
    BootProgressCode value;
    ipmi::DbusObjectInfo sbmrBootStateObject{};

    /* Get Boot State Object */
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, sbmrBootStateIntf, sbmrBootStateObject);
    if (ec.value())
    {
        lg2::error("Failed to get Boot State object, Error={ERROR}", "ERROR",
                   ec.message());
        return ipmi::responseUnspecifiedError();
    }

    /* Get Boot State property */
    ec = ipmi::getDbusProperty(ctx, sbmrBootStateObject.second,
                               sbmrBootStateObject.first, sbmrBootStateIntf,
                               "Value", value);
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

bool checkAllowedMediumType(uint8_t mediumType)
{
    if (mediumType ==
            static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20) ||
        mediumType ==
            static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface) ||
        mediumType == static_cast<uint8_t>(ipmi::EChannelMediumType::oem))
    {
        return true;
    }

    return false;
}

ipmi::Cc sbmrFilterCommands(ipmi::message::Request::ptr request)
{
    if (request->ctx->netFn != ipmi::netFnGroup ||
        request->ctx->group != ipmi::groupSBMR)
    {
        // Skip if not group SBMR
        return ipmi::ccSuccess;
    }

    ipmi::ChannelInfo chInfo;
    if (ipmi::getChannelInfo(request->ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info, channel={CHANNEL}", "CHANNEL",
                   request->ctx->channel);
        return ipmi::ccUnspecifiedError;
    }

    if (request->ctx->cmd == ipmi::sbmr::cmdSendBootProgressCode &&
        !checkAllowedMediumType(chInfo.mediumType))
    {
        lg2::error("Error - Medium interface not supported, medium={TYPE}",
                   "TYPE", chInfo.mediumType);
        return ipmi::ccCommandNotAvailable;
    }

    return ipmi::ccSuccess;
}

} // namespace ipmi

void registerNetfnSBMRFunctions()
{
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupSBMR,
                         ipmi::sbmr::cmdSendBootProgressCode,
                         ipmi::Privilege::Admin, ipmi::sendBootProgressCode);

    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupSBMR,
                         ipmi::sbmr::cmdGetBootProgressCode,
                         ipmi::Privilege::User, ipmi::getBootProgressCode);

    ipmi::registerFilter(ipmi::prioOemBase,
                         [](ipmi::message::Request::ptr request) {
                             return ipmi::sbmrFilterCommands(request);
                         });
}
