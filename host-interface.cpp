#include <phosphor-logging/log.hpp>
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

// TODO - Add timeout function?
//          - If host does not respond to SMS, need to signal a failure
//      - Flush queue on power off?  - Timeout would do this for us for free
//      - Ignore requests when host state not running? - Timeout handles too

void Host::checkQueue()
{
    // If this was the only entry then send the SMS attention
    if(this->workQueue.size() >= 1)
    {
        log<level::INFO>("Asserting SMS Attention");

        std::string HOST_PATH("/org/openbmc/HostIpmi/1");
        std::string HOST_INTERFACE("org.openbmc.HostIpmi");

        auto mapper = this->bus.new_method_call(MAPPER_BUSNAME,
                                                MAPPER_PATH,
                                                MAPPER_INTERFACE,
                                                "GetObject");

        mapper.append(HOST_PATH, std::vector<std::string>({HOST_INTERFACE}));
        auto mapperResponseMsg = this->bus.call(mapper);

        if (mapperResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in mapper call for HostIpmi interface");
            return;
        }

        std::map<std::string, std::vector<std::string>> mapperResponse;
        mapperResponseMsg.read(mapperResponse);
        if (mapperResponse.empty())
        {
            log<level::ERR>("Error reading mapper response for HostIpmi interface");
            return;
        }

        const auto& host = mapperResponse.begin()->first;

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

    // TODO - Does sdbusplus guarantee 1 at a time calls to this interface or
    //        do we need some mutex protection around the push and size check?
    this->workQueue.push(command);

    // Alert host if this is only command in queue otherwise host will
    // be notified of next message after processing the current one
    if(this->workQueue.size() == 1)
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
