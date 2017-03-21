#include <queue>
#include <phosphor-logging/log.hpp>
#include "host-interface.hpp"

namespace phosphor
{
namespace host
{

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
    return;
}

} // namespace host
} // namepsace phosphor
