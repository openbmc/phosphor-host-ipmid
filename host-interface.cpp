#include <functional>
#include <systemintfcmds.h>
#include <host-ipmid/ipmid-host-cmd.hpp>
#include <host-ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <config.h>
#include <host-interface.hpp>
namespace phosphor
{
namespace host
{
namespace command
{

// When you see Base:: you know we're referencing our base class
namespace Base = sdbusplus::xyz::openbmc_project::Control::server;

// Maps IPMI command to it's counterpart in interface
const std::map<uint8_t, Host::Command> Host::intfCommand = {
    {
        CMD_HEARTBEAT,
            Base::Host::Command::Heartbeat
    },
    {
        CMD_POWER,
            Base::Host::Command::SoftOff
    }
};

// Maps Interface command to it's counterpart per IPMI
const std::map<Host::Command, IpmiCmdData> Host::ipmiCommand = {
    {
        Base::Host::Command::Heartbeat,
            std::make_pair(CMD_HEARTBEAT, 0x00)
    },
    {
        Base::Host::Command::SoftOff,
            std::make_pair(CMD_POWER, SOFT_OFF)
    }
};

// Called at user request
void Host::execute(Base::Host::Command command)
{
    using namespace phosphor::logging;

    log<level::INFO>("Pushing cmd on to queue",
            entry("CONTROL_HOST_CMD=%s",
                  convertForMessage(command)));

    auto cmd = std::make_tuple(ipmiCommand.at(command),
                        std::bind(&Host::commandStatusHandler,
                            this, std::placeholders::_1,
                                std::placeholders::_2));

    return cmdManager->execute(cmd);
}

// Called into by Command Manager
void Host::commandStatusHandler(IpmiCmdData cmd, bool status)
{
    // Need to convert <cmd> to the equivalent one mentioned in spec
    auto value = status ? Result::Success : Result::Failure;

    // Fire a signal
    this->commandComplete(intfCommand.at(std::get<0>(cmd)), value);
}

} // namespace command
} // namespace host
} // namepsace phosphor
