/**
 * Copyright © 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#include "settings.hpp"

#include <dlfcn.h>

#include <algorithm>
#include <any>
#include <exception>
#include <forward_list>
#include <host-cmd-manager.hpp>
#include <host-ipmid/ipmid-host-cmd.hpp>
#include <host-ipmid/oemrouter.hpp>
#include <ipmi/handler.hpp>
#include <ipmi/ipmi-api.hpp>
#include <ipmi/message.hpp>
#include <ipmi/registration.hpp>
#include <map>
#include <memory>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/sd_event.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/timer.hpp>
#include <tuple>
#include <types.hpp>
#include <unordered_map>
#include <utility>
#include <vector>

#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace std
{
// splice experimental::filesystem into std
namespace filesystem = std::experimental::filesystem;
} // namespace std
#else
#error filesystem not available
#endif

namespace fs = std::filesystem;

using namespace phosphor::logging;

// Global timer for network changes
std::unique_ptr<phosphor::Timer> networkTimer = nullptr;

// IPMI Spec, shared Reservation ID.
static unsigned short selReservationID = 0xFFFF;
static bool selReservationValid = false;

unsigned short reserveSel(void)
{
    // IPMI spec, Reservation ID, the value simply increases against each
    // execution of the Reserve SEL command.
    if (++selReservationID == 0)
    {
        selReservationID = 1;
    }
    selReservationValid = true;
    return selReservationID;
}

bool checkSELReservation(unsigned short id)
{
    return (selReservationValid && selReservationID == id);
}

void cancelSELReservation(void)
{
    selReservationValid = false;
}

EInterfaceIndex getInterfaceIndex(void)
{
    return interfaceKCS;
}

sd_bus* bus;
sd_event* events = nullptr;
sd_event* ipmid_get_sd_event_connection(void)
{
    return events;
}
sd_bus* ipmid_get_sd_bus_connection(void)
{
    return bus;
}

namespace ipmi
{

static inline unsigned int makeCmdKey(unsigned int cluster, unsigned int cmd)
{
    return (cluster << 16) | cmd;
}

using HandlerTuple = std::tuple<int,                         /* prio */
                                Privilege, HandlerBase::ptr, /* handler */
                                std::any                     /* ctx */
                                >;

/* map to handle standard registered commands */
static std::unordered_map<unsigned int, /* key is NetFn/Cmd */
                          HandlerTuple>
    handlerMap;

namespace impl
{
/* common function to register all standard IPMI handlers */
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
                     HandlerBase::ptr handler, std::any& ctx)
{
    // check for valid NetFn: even; 00-0Ch, 30-3Eh
    if (netFn & 1 || (netFn > netFnTransport && netFn < netFnGroup) ||
        netFn > netFnOemEight)
    {
        // TODO: log an error, throw, what?
        return;
    }

    // create key and value for this handler
    unsigned int netFnCmd = makeCmdKey(netFn, cmd);
    HandlerTuple item(prio, priv, handler, ctx);

    // consult the handler map and look for a match
    auto& mapCmd = handlerMap[netFnCmd];
    if (!std::get<HandlerBase::ptr>(mapCmd))
    {
        mapCmd = item;
    }
    else if (std::get<0>(mapCmd) <= prio)
    {
        mapCmd = item;
    }
}

} // namespace impl

message::Response::ptr executeIpmiCommand(message::Request::ptr request)
{
    // the command has already passed through filter; execute it
    NetFn netFn = request->ctx->netFn;
    Cmd cmd = request->ctx->cmd;

    /* normal IPMI command */
    unsigned int key = makeCmdKey(netFn, cmd);
    auto cmdIter = handlerMap.find(key);
    if (cmdIter != handlerMap.end())
    {
        HandlerTuple& chosen = cmdIter->second;
        if (request->ctx->priv < std::get<Privilege>(chosen))
        {
            return errorResponse(request, ccInsufficientPrivilege);
        }
        return std::get<HandlerBase::ptr>(chosen)->call(request);
    }
    else
    {
        unsigned int wildcard = makeCmdKey(netFn, cmdWildcard);
        cmdIter = handlerMap.find(wildcard);
        if (cmdIter != handlerMap.end())
        {
            HandlerTuple& chosen = cmdIter->second;
            if (request->ctx->priv < std::get<Privilege>(chosen))
            {
                return errorResponse(request, ccInsufficientPrivilege);
            }
            return std::get<HandlerBase::ptr>(chosen)->call(request);
        }
    }
    return errorResponse(request, ccInvalidCommand);
}

/* called from sdbus async server context */
auto executionEntry(boost::asio::yield_context yield, NetFn netFn, uint8_t lun,
                    Cmd cmd, std::vector<uint8_t>& data,
                    std::map<std::string, ipmi::Value>& options)
{
    auto ctx = std::make_shared<ipmi::Context>(netFn, cmd, 0, 0,
                                               ipmi::privilegeAdmin, &yield);
    auto request = std::make_shared<ipmi::message::Request>(ctx, data);
    auto response = executeIpmiCommand(request);

    // Responses in IPMI require a bit set.  So there ya go...
    netFn |= 0x01;
    return std::make_tuple(netFn, lun, cmd, response->cc, response->raw);
}

/** @struct IpmiProvider
 *
 *  RAII wrapper for dlopen so that dlclose gets called on exit
 */
struct IpmiProvider
{
  public:
    /** @brief address of the opened library */
    void* addr;
    std::string name;

    IpmiProvider() = delete;
    IpmiProvider(const IpmiProvider&) = delete;
    IpmiProvider& operator=(const IpmiProvider&) = delete;
    IpmiProvider(IpmiProvider&&) = delete;
    IpmiProvider& operator=(IpmiProvider&&) = delete;

    /** @brief dlopen a shared object file by path
     *  @param[in]  filename - path of shared object to open
     */
    explicit IpmiProvider(const char* fname) : addr(nullptr), name(fname)
    {
        log<level::DEBUG>("Open IPMI provider library",
                          entry("PROVIDER=%s", name.c_str()));
        try
        {
            addr = dlopen(name.c_str(), RTLD_NOW);
        }
        catch (std::exception& e)
        {
            log<level::ERR>("ERROR opening IPMI provider",
                            entry("PROVIDER=%s", name.c_str()),
                            entry("ERROR=%s", e.what()));
        }
        catch (...)
        {
            std::exception_ptr eptr = std::current_exception();
            try
            {
                std::rethrow_exception(eptr);
            }
            catch (std::exception& e)
            {
                log<level::ERR>("ERROR opening IPMI provider",
                                entry("PROVIDER=%s", name.c_str()),
                                entry("ERROR=%s", e.what()));
            }
        }
        if (!isOpen())
        {
            log<level::ERR>("ERROR opening IPMI provider",
                            entry("PROVIDER=%s", name.c_str()),
                            entry("ERROR=%s", dlerror()));
        }
    }

    ~IpmiProvider()
    {
        if (isOpen())
        {
            dlclose(addr);
        }
    }
    bool isOpen() const
    {
        return (nullptr != addr);
    }
};

// Plugin libraries need to contain .so either at the end or in the middle
#define ipmiPluginExtn ".so"

/* return a vector of self-closing library handles */
std::forward_list<IpmiProvider> loadProviders(const fs::path& ipmiLibsPath)
{
    std::vector<fs::path> libs;
    for (auto& libPath : fs::directory_iterator(ipmiLibsPath))
    {
        fs::path fname = libPath.path();
        while (fname.has_extension())
        {
            fs::path extn = fname.extension();
            if (extn == ipmiPluginExtn)
            {
                libs.push_back(libPath.path());
                break;
            }
            fname.replace_extension();
        }
    }
    std::sort(libs.begin(), libs.end());

    std::forward_list<IpmiProvider> handles;
    for (auto& lib : libs)
    {
#ifdef __IPMI_DEBUG__
        log<level::DEBUG>("Registering handler",
                          entry("HANDLER=%s", lib.c_str()));
#endif
        handles.emplace_front(lib.c_str());
    }
    return handles;
}

} // namespace ipmi

static std::shared_ptr<boost::asio::io_service> io;
std::shared_ptr<boost::asio::io_service> getIoService()
{
    return io;
}

void post_work(work_t work)
{
    io->post(work);
}

static std::shared_ptr<sdbusplus::asio::connection> sdbusp;
std::shared_ptr<sdbusplus::asio::connection> getSdBus()
{
    return sdbusp;
}

#ifdef ALLOW_DEPRECATED_API
/* legacy registration */
void ipmi_register_callback(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
                            ipmi_context_t context, ipmid_callback_t handler,
                            ipmi_cmd_privilege_t priv)
{
    auto h = ipmi::makeLegacyHandler(handler);
    // translate priv from deprecated enum to current
    ipmi::Privilege realPriv;
    switch (priv)
    {
        case PRIVILEGE_CALLBACK:
            realPriv = ipmi::privilegeCallback;
            break;
        case PRIVILEGE_USER:
            realPriv = ipmi::privilegeUser;
            break;
        case PRIVILEGE_OPERATOR:
            realPriv = ipmi::privilegeOperator;
            break;
        case PRIVILEGE_ADMIN:
            realPriv = ipmi::privilegeAdmin;
            break;
        case PRIVILEGE_OEM:
            realPriv = ipmi::privilegeOem;
            break;
        case SYSTEM_INTERFACE:
            realPriv = ipmi::privilegeAdmin;
            break;
        default:
            realPriv = ipmi::privilegeAdmin;
            break;
    }
    auto ctx = std::any();
    if (context)
    {
        ctx = std::any(context);
    }
    ipmi::impl::registerHandler(ipmi::prioOpenBmcBase, netFn, cmd, realPriv, h,
                                ctx);
}

/* legacy alternative to executionEntry */
void handleLegacyIpmiCommand(sdbusplus::message::message& m)
{
    unsigned char seq, netFn, lun, cmd;
    std::vector<uint8_t> data;

    m.read(seq, netFn, lun, cmd, data);

    auto ctx =
        std::make_shared<ipmi::Context>(netFn, cmd, 0, 0, ipmi::privilegeAdmin);
    auto request = std::make_shared<ipmi::message::Request>(ctx, data);

    auto response = ipmi::executeIpmiCommand(request);

    // Responses in IPMI require a bit set.  So there ya go...
    netFn |= 0x01;

    const char *dest, *path;
    constexpr const char* DBUS_INTF = "org.openbmc.HostIpmi";

    dest = m.get_sender();
    path = m.get_path();
    sdbusp->async_method_call([](boost::system::error_code ec) {}, dest, path,
                              DBUS_INTF, "sendMessage", seq, netFn, lun, cmd,
                              response->cc, response->raw);
}

#endif /* ALLOW_DEPRECATED_API */

// Calls host command manager to do the right thing for the command
using CommandHandler = phosphor::host::command::CommandHandler;
std::unique_ptr<phosphor::host::command::Manager> cmdManager;
void ipmid_send_cmd_to_host(CommandHandler&& cmd)
{
    return cmdManager->execute(std::move(cmd));
}

std::unique_ptr<phosphor::host::command::Manager>& ipmid_get_host_cmd_manager()
{
    return cmdManager;
}

int main(int argc, char* argv[])
{
    // Connect to system bus
    io = std::make_shared<boost::asio::io_service>();
    if (argc > 1 && std::string(argv[1]) == "-session")
    {
        sd_bus_default_user(&bus);
    }
    else
    {
        sd_bus_default_system(&bus);
    }
    sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus);
    sdbusp->request_name("xyz.openbmc_project.Ipmi.Host");

    // TODO: Hack to keep the sdEvents running.... Not sure why the sd_event
    //       queue stops running if we don't have a timer that keeps re-arming
    phosphor::Timer t2([]() { ; });
    t2.start(std::chrono::microseconds(500000), true);

    // TODO: Remove all vestiges of sd_event from phosphor-host-ipmid
    //       until that is done, add the sd_event wrapper to the io object
    sdbusplus::asio::sd_event_wrapper sdEvents(*io);

    cmdManager = std::make_unique<phosphor::host::command::Manager>(*sdbusp);

    // Register all command providers and filters
    auto handles = ipmi::loadProviders(HOST_IPMI_LIB_PATH);

    // Add bindings for inbound IPMI requests
    auto server = sdbusplus::asio::object_server(sdbusp);
    auto iface = server.add_interface("/xyz/openbmc_project/Ipmi",
                                      "xyz.openbmc_project.Ipmi.Server");
    iface->register_method("execute", ipmi::executionEntry);
    iface->initialize();

#ifdef ALLOW_DEPRECATED_API
    // listen on deprecated signal interface for kcs/bt commands
    constexpr const char* FILTER = "type='signal',interface='org.openbmc."
                                   "HostIpmi',member='ReceivedMessage'";
    sdbusplus::bus::match::match oldIpmiInterface(*sdbusp, FILTER,
                                                  handleLegacyIpmiCommand);
#endif /* ALLOW_DEPRECATED_API */

    io->run();

    // This avoids a warning about unused variables
    handles.clear();
    return 0;
}
