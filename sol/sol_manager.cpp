#include "sol_manager.hpp"

#include "main.hpp"
#include "sol_context.hpp"

#include <sys/socket.h>
#include <sys/un.h>

#include <chrono>
#include <cmath>
#include <phosphor-logging/log.hpp>

namespace sol
{

using namespace phosphor::logging;

CustomFD::~CustomFD()
{
    if (fd >= 0)
    {
        // Remove the host console descriptor from the sd_event_loop
        std::get<eventloop::EventLoop&>(singletonPool).stopHostConsole();
        close(fd);
    }
}

void Manager::initHostConsoleFd()
{
    struct sockaddr_un addr;
    int rc = 0;
    int fd = 0;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        log<level::ERR>("Failed to open the host console socket",
                        entry("ERRNO=%d", errno));
        throw std::runtime_error("Failed to open the host console socket");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(&addr.sun_path, &CONSOLE_SOCKET_PATH, CONSOLE_SOCKET_PATH_LEN);
    consoleFD = std::make_unique<CustomFD>(fd);
    auto& conFD = *(consoleFD.get());

    rc = connect(conFD(), (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0)
    {
        log<level::ERR>("Failed to connect to host console socket address",
                        entry("ERRNO=%d", errno));
        consoleFD.reset();
        throw std::runtime_error("Failed to connect to console server");
    }
}

int Manager::writeConsoleSocket(const std::vector<uint8_t>& input) const
{
    auto inBuffer = input.data();
    auto inBufferSize = input.size();
    size_t pos = 0;
    ssize_t rc = 0;
    int errVal = 0;
    auto& conFD = *(consoleFD.get());

    for (pos = 0; pos < inBufferSize; pos += rc)
    {
        rc = write(conFD(), inBuffer + pos, inBufferSize - pos);
        if (rc <= 0)
        {
            if (errno == EINTR)
            {
                log<level::INFO>(" Retrying to handle EINTR",
                                 entry("ERRNO=%d", errno));
                rc = 0;
                continue;
            }
            else
            {
                errVal = errno;
                log<level::ERR>("Failed to write to host console socket",
                                entry("ERRNO=%d", errno));
                return -errVal;
            }
        }
    }

    return 0;
}

void Manager::startPayloadInstance(uint8_t payloadInstance,
                                   session::SessionID sessionID)
{
    if (payloadMap.empty())
    {
        initHostConsoleFd();

        // Register the fd in the sd_event_loop
        std::get<eventloop::EventLoop&>(singletonPool)
            .startHostConsole(*(consoleFD.get()));
    }

    // Create the SOL Context data for payload instance
    auto context = std::make_unique<Context>(retryCount, sendThreshold,
                                             payloadInstance, sessionID);

    std::get<eventloop::EventLoop&>(singletonPool)
        .startSOLPayloadInstance(
            payloadInstance,
            std::chrono::duration_cast<eventloop::IntervalType>(
                accumulateInterval),
            std::chrono::duration_cast<eventloop::IntervalType>(retryInterval));

    payloadMap.emplace(payloadInstance, std::move(context));
}

void Manager::stopPayloadInstance(uint8_t payloadInstance)
{
    auto iter = payloadMap.find(payloadInstance);
    if (iter == payloadMap.end())
    {
        throw std::runtime_error("SOL Payload instance not found ");
    }

    payloadMap.erase(iter);

    std::get<eventloop::EventLoop&>(singletonPool)
        .stopSOLPayloadInstance(payloadInstance);

    if (payloadMap.empty())
    {
        consoleFD.reset();

        dataBuffer.erase(dataBuffer.size());
    }
}

} // namespace sol
