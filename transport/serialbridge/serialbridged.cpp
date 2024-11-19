#include "serialcmd.hpp"

#include <systemd/sd-daemon.h>

#include <CLI/CLI.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/interface.hpp>
#include <sdbusplus/slot.hpp>
#include <sdbusplus/vtable.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/signal.hpp>
#include <stdplus/exception.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/ops.hpp>
#include <stdplus/signal.hpp>

namespace serialbridge
{

using sdeventplus::source::IO;
using sdeventplus::source::Signal;
using stdplus::fd::OpenAccess;
using stdplus::fd::OpenFlag;
using stdplus::fd::OpenFlags;

constexpr sdbusplus::vtable::vtable_t dbusMethods[] = {
    sdbusplus::vtable::start(),
    sdbusplus::vtable::end(),
};

int execute(const std::string& channel)
{
    // Set up DBus and event loop
    auto event = sdeventplus::Event::get_default();
    auto bus = sdbusplus::bus::new_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Configure basic signal handling
    auto exit_handler = [&event](Signal&, const struct signalfd_siginfo*) {
        fmt::print(stderr, "Interrupted, Exiting\n");
        event.exit(0);
    };
    stdplus::signal::block(SIGINT);
    Signal sig_init(event, SIGINT, exit_handler);
    stdplus::signal::block(SIGTERM);
    Signal sig_term(event, SIGTERM, exit_handler);

    // Open an FD for the UART channel
    stdplus::ManagedFd uart = stdplus::fd::open(
        std::format("/dev/{}", channel.c_str()),
        OpenFlags(OpenAccess::ReadWrite).set(OpenFlag::NonBlock));
    sdbusplus::slot_t slot(nullptr);

    // Add a reader to the bus for handling inbound IPMI
    IO ioSource(
        event, uart.get(), EPOLLIN | EPOLLET,
        stdplus::exception::ignore([&uart, &bus, &slot](IO&, int, uint32_t) {
            read(uart, bus, slot);
        }));

    // Allow processes to affect the state machine
    std::string dbusChannel = "ipmi_serial";
    auto obj = "/xyz/openbmc_project/Ipmi/Channel/" + dbusChannel;
    auto srv = "xyz.openbmc_project.Ipmi.Channel." + dbusChannel;
    auto intf = sdbusplus::server::interface::interface(
        bus, obj.c_str(), "xyz.openbmc_project.Ipmi.Channel.ipmi_serial",
        dbusMethods, nullptr);

    bus.request_name(srv.c_str());

    sd_notify(0, "READY=1");
    return event.loop();
}

} // namespace serialbridge

int main(int argc, char* argv[])
{
    std::string device = "ttyAMA0";
    bool verbose = 0;

    // Parse input parameter
    CLI::App app("Serial IPMI Bridge");
    app.add_option("-d,--device", device,
                   "select uart device, default is ttyAMA0");
    app.add_option("-v,--verbose", verbose, "enable debug message");
    CLI11_PARSE(app, argc, argv);

    try
    {
        serialbridge::setVerbose(verbose);
        return serialbridge::execute(device);
    }
    catch (const std::exception& e)
    {
        stdplus::print(stderr, "FAILED: {}\n", e.what());
        return 1;
    }
}
