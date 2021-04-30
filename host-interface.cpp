
#include "config.h"

#include "host-interface.hpp"

#include "systemintfcmds.hpp"

#include <functional>
#include <future>
#include <ipmid-host/cmd-utils.hpp>
#include <ipmid-host/cmd.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>

namespace phosphor
{
namespace host
{
namespace command
{

using namespace phosphor::logging;

// When you see Base:: you know we're referencing our base class
namespace Base = sdbusplus::xyz::openbmc_project::Control::server;

// IPMI OEM command.
// https://github.com/openbmc/openbmc/issues/2082 for handling
// Non-OEM commands that need to send SMS_ATN
using OEMCmd = uint8_t;

// Map of IPMI OEM command to its equivalent interface command.
// This is needed when invoking the callback handler to indicate
// the status of the executed command.
static const std::map<OEMCmd, Host::Command> intfCommand = {
    {CMD_HEARTBEAT, Base::Host::Command::Heartbeat},
    {CMD_POWER, Base::Host::Command::SoftOff}};

// Map of Interface command to its corresponding IPMI OEM command.
// This is needed when pushing IPMI commands to command manager's
// queue. The same pair will be returned when IPMI asks us
// why a SMS_ATN was sent
static const std::map<Host::Command, IpmiCmdData> ipmiCommand = {
    {Base::Host::Command::Heartbeat, std::make_pair(CMD_HEARTBEAT, 0x00)},
    {Base::Host::Command::SoftOff, std::make_pair(CMD_POWER, SOFT_OFF)}};

// Called at user request
void Host::execute(Base::Host::Command command)
{
    log<level::DEBUG>(
        "Pushing cmd on to queue",
        entry("CONTROL_HOST_CMD=%s", convertForMessage(command).c_str()));

    auto cmd = std::make_tuple(ipmiCommand.at(command),
                               std::bind(&Host::commandStatusHandler, this,
                                         std::placeholders::_1,
                                         std::placeholders::_2));

    ipmid_send_cmd_to_host(std::move(cmd));
}

// Called into by Command Manager
void Host::commandStatusHandler(IpmiCmdData cmd, bool status)
{
    // Need to convert <cmd> to the equivalent one mentioned in spec
    auto value = status ? Result::Success : Result::Failure;

    // Fire a signal
    this->commandComplete(intfCommand.at(std::get<0>(cmd)), value);
}

Host::FirmwareCondition Host::currentFirmwareCondition() const
{
    // Promise used to coordinate host status
    // Lambdas can not have captures passed when being utilized for a function
    // callback. Therefore this just needs to be a local static.
    static std::promise<Host::FirmwareCondition> hostConditionPromise;

    // Default is host firmware is not running
    auto result = Host::FirmwareCondition::Off;

    std::future<Host::FirmwareCondition> hostConditionFuture =
        hostConditionPromise.get_future();

    // callback for command to host
    auto hostAckCallback = [](IpmiCmdData cmd, bool status) {
        auto value = status ? Host::FirmwareCondition::Running
                            : Host::FirmwareCondition::Off;

        log<level::INFO>("currentFirmwareCondition:hostAckCallback fired",
                         entry("CONTROL_HOST_CMD=%i", value));

        hostConditionPromise.set_value(value);
        return;
    };

    auto cmd = std::make_tuple(ipmiCommand.at(Base::Host::Command::Heartbeat),
                               hostAckCallback);

    ipmid_send_cmd_to_host(std::move(cmd));

    auto io = getIoContext();

    // Loop 1 second past the ATN_ACK timeout to ensure we wait for as
    // long as the timeout
    for (int i = 0; i < IPMI_SMS_ATN_ACK_TIMEOUT_SECS + 1; i++)
    {
        io->run_for(std::chrono::seconds(1));

        std::future_status status =
            hostConditionFuture.wait_for(std::chrono::microseconds(1));
        if (status == std::future_status::ready)
        {
            log<level::INFO>("currentFirmwareCondition: future is ready!");
            result = hostConditionFuture.get();
            break;
        }
        log<level::INFO>(
            "currentFirmwareCondition: still waiting for host response");
    }

    // Always create a new promise for the next call
    hostConditionPromise = std::promise<Host::FirmwareCondition>();

    return (result);
}

} // namespace command
} // namespace host
} // namespace phosphor
