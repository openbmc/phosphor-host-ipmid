#include <queue>
#include <phosphor-logging/log.hpp>
#include <utils.hpp>
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

std::queue<base::Host::Command> workQueue{};

void Host::execute(base::Host::Command command)
{
    log<level::INFO>("Pushing cmd on to queue",
            entry("CONTROL_HOST_CMD=%s",
                  convertForMessage(command)));
    workQueue.push(command);

    // If this was the only entry then send the SMS attention
    if(workQueue.size() == 1)
    {
        log<level::INFO>("Asserting SMS Attention");

        std::string IPMI_PATH("/org/openbmc/HostIpmi/1");
        std::string IPMI_INTERFACE("org.openbmc.HostIpmi");

        auto host = ipmi::getService(this->bus,IPMI_INTERFACE,IPMI_PATH);

        auto method = this->bus.new_method_call(host.c_str(),
                                                IPMI_PATH.c_str(),
                                                IPMI_INTERFACE.c_str(),
                                                "setAttention");
        auto reply = this->bus.call(method);

        if (reply.is_method_error())
        {
            log<level::ERR>("Error in setting SMS attention");
            throw std::runtime_error("ERROR in call to setAttention");
        }
        log<level::INFO>("SMS Attention asserted");
    }

    return;
}

} // namespace host
} // namepsace phosphor
