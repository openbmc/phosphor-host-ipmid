#include <chrono>
#include <phosphor-logging/log.hpp>
#include <utils.hpp>
#include <config.h>
#include "host-interface.hpp"

namespace phosphor
{
namespace host
{

constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;

// When you see base:: you know we're referencing our base class
namespace base = sdbusplus::xyz::openbmc_project::Control::server;

base::Host::Command Host::getNextCommand()
{
    // Stop the timer
    auto r = timer.setTimer(SD_EVENT_OFF);
    if (r < 0)
    {
        log<level::ERR>("Failure to STOP the timer",
                entry("ERROR=%s", strerror(-r)));
    }

    if(this->workQueue.empty())
    {
        throw std::runtime_error("Control Host work queue is empty!");
    }

    // Pop the processed entry off the queue
    Command command = this->workQueue.front();
    this->workQueue.pop();

    // Issue command complete signal
    this->commandComplete(command, Result::Success);

    // Check for another entry in the queue and kick it off
    this->checkQueue();
    return command;
}

void *Host::hostTimeout()
{
    log<level::ERR>("Host control timeout hit!");
    // Dequeue all entries and send fail signal
    while(!this->workQueue.empty())
    {
        auto command = this->workQueue.front();
        this->workQueue.pop();
        this->commandComplete(command,Result::Failure);
    }
    return nullptr;
}

void Host::checkQueue()
{
    if (this->workQueue.size() >= 1)
    {
        log<level::INFO>("Asserting SMS Attention");

        std::string HOST_PATH("/org/openbmc/HostIpmi/1");
        std::string HOST_INTERFACE("org.openbmc.HostIpmi");

        auto host = ::ipmi::getService(this->bus,HOST_INTERFACE,HOST_PATH);

        // Start the timer for this transaction
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::seconds(IPMI_SMS_ATN_ACK_TIMEOUT_SECS));
        auto r = timer.startTimer(time);
        if (r < 0)
        {
            log<level::ERR>("Error starting timer for control host");
            return;
        }

        auto method = this->bus.new_method_call(host.c_str(),
                                                HOST_PATH.c_str(),
                                                HOST_INTERFACE.c_str(),
                                                "setAttention");
        auto reply = this->bus.call(method);

        if (reply.is_method_error())
        {
            log<level::ERR>("Error in setting SMS attention");
            return;
        }
        log<level::INFO>("SMS Attention asserted");
    }
}

void Host::execute(base::Host::Command command)
{
    log<level::INFO>("Pushing cmd on to queue",
            entry("CONTROL_HOST_CMD=%s",
                  convertForMessage(command)));

    this->workQueue.push(command);

    // Alert host if this is only command in queue otherwise host will
    // be notified of next message after processing the current one
    if (this->workQueue.size() == 1)
    {
        this->checkQueue();
    }
    else
    {
        log<level::INFO>("Command in process, no attention");
    }

    return;
}

} // namespace host
} // namepsace phosphor
