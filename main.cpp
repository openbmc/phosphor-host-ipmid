#include "main.hpp"
#include <assert.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>

#include <iostream>
#include <tuple>

#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <host-ipmid/ipmid-api.h>
#include "comm_module.hpp"
#include "command_table.hpp"
#include "message.hpp"
#include "message_handler.hpp"
#include "sessions_manager.hpp"
#include "socket_channel.hpp"

// Tuple of Global Singletons
session::Manager manager;
command::Table table;
std::tuple<session::Manager&, command::Table&> singletonPool(manager, table);

sd_bus* bus = nullptr;

/*
 * @brief Required by apphandler IPMI Provider Library
 */
sd_bus* ipmid_get_sd_bus_connection()
{
    return bus;
}

/*
 * TODO : The plan is to refactor the event loop to support adding multiple
 * file descriptors and event handlers for implementing the Serial Over LAN.
 *
 * A class would abstract the features provided by the sd_event_loop
 */

namespace eventloop
{

static int io_handler(sd_event_source* es, int fd, uint32_t revents,
                      void* userdata)
{
    std::shared_ptr<udpsocket::Channel> channelPtr;
    struct timeval timeout;
    timeout.tv_sec = SELECT_CALL_TIMEOUT;
    timeout.tv_usec = 0;

    channelPtr.reset(new udpsocket::Channel(fd, timeout));

    // Initialize the Message Handler with the socket channel
    message::Handler msgHandler(channelPtr);

    // Read the incoming IPMI packet
    std::unique_ptr<message::Message> inMessage;
    try
    {
        inMessage = msgHandler.receive();
    }
    catch (std::exception& e)
    {
        std::cerr << "Reading & Parsing the incoming IPMI message failed\n";
        std::cerr << e.what() << "\n";
        return 0;
    }

    // Execute the Command
    auto outMessage = msgHandler.executeCommand(*inMessage.get());
    if (outMessage == nullptr)
    {
        std::cerr << "Execution of IPMI command failed\n";
        return 0;
    }

    // Send the response IPMI Message
    msgHandler.send(*outMessage.get());

    return 0;
}

int startEventLoop()
{
    struct sockaddr_in6 in {};

    sd_event_source* event_source = nullptr;
    sd_event* event = nullptr;
    int fd = -1, r;
    sigset_t ss;

    r = sd_event_default(&event);
    if (r < 0)
    {
        goto finish;
    }

    if (sigemptyset(&ss) < 0 || sigaddset(&ss, SIGTERM) < 0 ||
        sigaddset(&ss, SIGINT) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Block SIGTERM first, so that the event loop can handle it */
    if (sigprocmask(SIG_BLOCK, &ss, nullptr) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Let's make use of the default handler and "floating" reference features
     * of sd_event_add_signal() */
    r = sd_event_add_signal(event, nullptr, SIGTERM, nullptr, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_add_signal(event, nullptr, SIGINT, nullptr, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
    {
        r = -errno;
        goto finish;
    }

    in.sin6_family = AF_INET6;
    in.sin6_port = htons(IPMI_STD_PORT);

    if (bind(fd, (struct sockaddr*)&in, sizeof(in)) < 0)
    {
        r = -errno;
        goto finish;
    }

    r = sd_event_add_io(event, &event_source, fd, EPOLLIN, io_handler, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_loop(event);

finish:
    event_source = sd_event_source_unref(event_source);
    event = sd_event_unref(event);

    if (fd >= 0)
    {
        (void) close(fd);
    }

    if (r < 0)
    {
        fprintf(stderr, "Failure: %s\n", strerror(-r));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

} // namespace eventloop

int main(int i_argc, char* i_argv[])
{
    // Connect to system bus
    auto rc = sd_bus_open_system(&bus);
    if (rc < 0)
    {
        std::cerr << "Failed to connect to system bus:" << strerror(-rc) <<"\n";
        goto finish;
    }

    // Register the phosphor-net-ipmid session setup commands
    command::sessionSetupCommands();

    // Start Event Loop
    return eventloop::startEventLoop();

finish:
    sd_bus_unref(bus);

    return 0;
}
