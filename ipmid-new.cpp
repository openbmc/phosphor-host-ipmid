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
#include <ipmid-host/cmd.hpp>
#include <ipmid/api.hpp>
#include <ipmid/handler.hpp>
#include <ipmid/message.hpp>
#include <ipmid/oemrouter.hpp>
#include <ipmid/registration.hpp>
#include <ipmid/types.hpp>
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
    return (cluster << 8) | cmd;
}

using HandlerTuple = std::tuple<int,                        /* prio */
                                Privilege, HandlerBase::ptr /* handler */
                                >;

/* map to handle standard registered commands */
static std::unordered_map<unsigned int, /* key is NetFn/Cmd */
                          HandlerTuple>
    handlerMap;

/* special map for decoding Group registered commands (NetFn 2Ch) */
static std::unordered_map<unsigned int, /* key is Group/Cmd (NetFn is 2Ch) */
                          HandlerTuple>
    groupHandlerMap;

/* special map for decoding OEM registered commands (NetFn 2Eh) */
static std::unordered_map<unsigned int, /* key is Iana/Cmd (NetFn is 2Eh) */
                          HandlerTuple>
    oemHandlerMap;

using FilterTuple = std::tuple<int,            /* prio */
                               FilterBase::ptr /* filter */
                               >;

/* list to hold all registered ipmi command filters */
static std::forward_list<FilterTuple> filterList;

namespace impl
{
/* common function to register all standard IPMI handlers */
bool registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
                     HandlerBase::ptr handler)
{
    // check for valid NetFn: even; 00-0Ch, 30-3Eh
    if (netFn & 1 || (netFn > netFnTransport && netFn < netFnGroup) ||
        netFn > netFnOemEight)
    {
        return false;
    }

    // create key and value for this handler
    unsigned int netFnCmd = makeCmdKey(netFn, cmd);
    HandlerTuple item(prio, priv, handler);

    // consult the handler map and look for a match
    auto& mapCmd = handlerMap[netFnCmd];
    if (!std::get<HandlerBase::ptr>(mapCmd) || std::get<int>(mapCmd) <= prio)
    {
        mapCmd = item;
        return true;
    }
    return false;
}

/* common function to register all Group IPMI handlers */
bool registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
                          HandlerBase::ptr handler)
{
    // create key and value for this handler
    unsigned int netFnCmd = makeCmdKey(group, cmd);
    HandlerTuple item(prio, priv, handler);

    // consult the handler map and look for a match
    auto& mapCmd = groupHandlerMap[netFnCmd];
    if (!std::get<HandlerBase::ptr>(mapCmd) || std::get<int>(mapCmd) <= prio)
    {
        mapCmd = item;
        return true;
    }
    return false;
}

/* common function to register all OEM IPMI handlers */
bool registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
                        HandlerBase::ptr handler)
{
    // create key and value for this handler
    unsigned int netFnCmd = makeCmdKey(iana, cmd);
    HandlerTuple item(prio, priv, handler);

    // consult the handler map and look for a match
    auto& mapCmd = oemHandlerMap[netFnCmd];
    if (!std::get<HandlerBase::ptr>(mapCmd) || std::get<int>(mapCmd) <= prio)
    {
        mapCmd = item;
        return true;
    }
    return false;
}

/* common function to register all IPMI filter handlers */
void registerFilter(int prio, FilterBase::ptr filter)
{
    // check for initial placement
    if (filterList.empty() || std::get<int>(filterList.front()) < prio)
    {
        filterList.emplace_front(std::make_tuple(prio, filter));
    }
    // walk the list and put it in the right place
    auto j = filterList.begin();
    for (auto i = j; i != filterList.end() && std::get<int>(*i) > prio; i++)
    {
        j = i;
    }
    filterList.emplace_after(j, std::make_tuple(prio, filter));
}

} // namespace impl

message::Response::ptr filterIpmiCommand(message::Request::ptr request)
{
    // pass the command through the filter mechanism
    // This can be the firmware firewall or any OEM mechanism like
    // whitelist filtering based on operational mode
    for (auto& item : filterList)
    {
        FilterBase::ptr filter = std::get<FilterBase::ptr>(item);
        ipmi::Cc cc = filter->call(request);
        if (ipmi::ccSuccess != cc)
        {
            return errorResponse(request, cc);
        }
    }
    return message::Response::ptr();
}

message::Response::ptr executeIpmiCommandCommon(
    std::unordered_map<unsigned int, HandlerTuple>& handlers,
    unsigned int keyCommon, message::Request::ptr request)
{
    // filter the command first; a non-null message::Response::ptr
    // means that the message has been rejected for some reason
    message::Response::ptr response = filterIpmiCommand(request);
    if (response)
    {
        return response;
    }

    Cmd cmd = request->ctx->cmd;
    unsigned int key = makeCmdKey(keyCommon, cmd);
    auto cmdIter = handlers.find(key);
    if (cmdIter != handlers.end())
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
        unsigned int wildcard = makeCmdKey(keyCommon, cmdWildcard);
        cmdIter = handlers.find(wildcard);
        if (cmdIter != handlers.end())
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

message::Response::ptr executeIpmiGroupCommand(message::Request::ptr request)
{
    // look up the group for this request
    Group group;
    if (0 != request->payload.unpack(group))
    {
        return errorResponse(request, ccReqDataLenInvalid);
    }
    // The handler will need to unpack group as well; we just need it for lookup
    request->payload.reset();
    message::Response::ptr response =
        executeIpmiCommandCommon(groupHandlerMap, group, request);
    // if the handler should add the group; executeIpmiCommandCommon does not
    if (response->cc != ccSuccess && response->payload.size() == 0)
    {
        response->pack(group);
    }
    return response;
}

message::Response::ptr executeIpmiOemCommand(message::Request::ptr request)
{
    // look up the iana for this request
    Iana iana;
    if (0 != request->payload.unpack(iana))
    {
        return errorResponse(request, ccReqDataLenInvalid);
    }
    request->payload.reset();
    message::Response::ptr response =
        executeIpmiCommandCommon(oemHandlerMap, iana, request);
    // if the handler should add the iana; executeIpmiCommandCommon does not
    if (response->cc != ccSuccess && response->payload.size() == 0)
    {
        response->pack(iana);
    }
    return response;
}

message::Response::ptr executeIpmiCommand(message::Request::ptr request)
{
    NetFn netFn = request->ctx->netFn;
    if (netFnGroup == netFn)
    {
        return executeIpmiGroupCommand(request);
    }
    else if (netFnOem == netFn)
    {
        return executeIpmiOemCommand(request);
    }
    return executeIpmiCommandCommon(handlerMap, netFn, request);
}

/* called from sdbus async server context */
auto executionEntry(boost::asio::yield_context yield, NetFn netFn, uint8_t lun,
                    Cmd cmd, std::vector<uint8_t>& data,
                    std::map<std::string, ipmi::Value>& options)
{
    auto ctx = std::make_shared<ipmi::Context>(netFn, cmd, 0, 0,
                                               ipmi::Privilege::Admin, &yield);
    auto request = std::make_shared<ipmi::message::Request>(
        ctx, std::forward<std::vector<uint8_t>>(data));
    message::Response::ptr response = executeIpmiCommand(request);

    // Responses in IPMI require a bit set.  So there ya go...
    netFn |= 0x01;
    return std::make_tuple(netFn, lun, cmd, response->cc,
                           response->payload.raw);
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
constexpr const char ipmiPluginExtn[] = ".so";

/* return a list of self-closing library handles */
std::forward_list<IpmiProvider> loadProviders(const fs::path& ipmiLibsPath)
{
    std::vector<fs::path> libs;
    for (const auto& libPath : fs::directory_iterator(ipmiLibsPath))
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

#ifdef ALLOW_DEPRECATED_API
/* legacy registration */
void ipmi_register_callback(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
                            ipmi_context_t context, ipmid_callback_t handler,
                            ipmi_cmd_privilege_t priv)
{
    auto h = ipmi::makeLegacyHandler(handler, context);
    // translate priv from deprecated enum to current
    ipmi::Privilege realPriv;
    switch (priv)
    {
        case PRIVILEGE_CALLBACK:
            realPriv = ipmi::Privilege::Callback;
            break;
        case PRIVILEGE_USER:
            realPriv = ipmi::Privilege::User;
            break;
        case PRIVILEGE_OPERATOR:
            realPriv = ipmi::Privilege::Operator;
            break;
        case PRIVILEGE_ADMIN:
            realPriv = ipmi::Privilege::Admin;
            break;
        case PRIVILEGE_OEM:
            realPriv = ipmi::Privilege::Oem;
            break;
        case SYSTEM_INTERFACE:
            realPriv = ipmi::Privilege::Admin;
            break;
        default:
            realPriv = ipmi::Privilege::Admin;
            break;
    }
    // The original ipmi_register_callback allowed for group OEM handlers
    // to be registered via this same interface... pretend to do the same
    if (netFn == NETFUN_OEM_GROUP)
    {
        ipmi::impl::registerGroupHandler(ipmi::prioOpenBmcBase, 0, cmd,
                                         realPriv, h);
    }
    else
    {
        ipmi::impl::registerHandler(ipmi::prioOpenBmcBase, netFn, cmd, realPriv,
                                    h);
    }
}

namespace oem
{

class LegacyRouter : public oem::Router
{
  public:
    virtual ~LegacyRouter()
    {
    }

    /// Enable message routing to begin.
    void activate() override
    {
    }

    void registerHandler(Number oen, ipmi_cmd_t cmd, Handler handler) override
    {
        auto h = ipmi::makeLegacyHandler(std::forward<Handler>(handler));
        ipmi::impl::registerOemHandler(ipmi::prioOpenBmcBase, oen, cmd,
                                       ipmi::Privilege::Admin, h);
    }
};
static LegacyRouter legacyRouter;

Router* mutableRouter()
{
    return &legacyRouter;
}

} // namespace oem

/* legacy alternative to executionEntry */
void handleLegacyIpmiCommand(sdbusplus::message::message& m)
{
    unsigned char seq, netFn, lun, cmd;
    std::vector<uint8_t> data;

    m.read(seq, netFn, lun, cmd, data);

    auto ctx = std::make_shared<ipmi::Context>(netFn, cmd, 0, 0,
                                               ipmi::Privilege::Admin);
    auto request = std::make_shared<ipmi::message::Request>(
        ctx, std::forward<std::vector<uint8_t>>(data));
    ipmi::message::Response::ptr response = ipmi::executeIpmiCommand(request);

    // Responses in IPMI require a bit set.  So there ya go...
    netFn |= 0x01;

    const char *dest, *path;
    constexpr const char* DBUS_INTF = "org.openbmc.HostIpmi";

    dest = m.get_sender();
    path = m.get_path();
    getSdBus()->async_method_call([](boost::system::error_code ec) {}, dest,
                                  path, DBUS_INTF, "sendMessage", seq, netFn,
                                  lun, cmd, response->cc,
                                  response->payload.raw);
}

#endif /* ALLOW_DEPRECATED_API */

// Calls host command manager to do the right thing for the command
using CommandHandler = phosphor::host::command::CommandHandler;
std::unique_ptr<phosphor::host::command::Manager> cmdManager;
void ipmid_send_cmd_to_host(CommandHandler&& cmd)
{
    return cmdManager->execute(std::forward<CommandHandler>(cmd));
}

std::unique_ptr<phosphor::host::command::Manager>& ipmid_get_host_cmd_manager()
{
    return cmdManager;
}

// These are symbols that are present in libipmid, but not expected
// to be used except here (or maybe a unit test), so declare them here
extern void setIoContext(std::shared_ptr<boost::asio::io_context>& newIo);
extern void setSdBus(std::shared_ptr<sdbusplus::asio::connection>& newBus);

int main(int argc, char* argv[])
{
    // Connect to system bus
    auto io = std::make_shared<boost::asio::io_context>();
    setIoContext(io);
    if (argc > 1 && std::string(argv[1]) == "-session")
    {
        sd_bus_default_user(&bus);
    }
    else
    {
        sd_bus_default_system(&bus);
    }
    auto sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus);
    setSdBus(sdbusp);
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
    std::forward_list<ipmi::IpmiProvider> providers =
        ipmi::loadProviders(HOST_IPMI_LIB_PATH);

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

    // set up boost::asio signal handling
    std::function<SignalResponse(int)> stopAsioRunLoop =
        [&io](int signalNumber) {
            log<level::INFO>("Received signal; quitting",
                             entry("SIGNAL=%d", signalNumber));
            io->stop();
            return SignalResponse::breakExecution;
        };
    registerSignalHandler(ipmi::prioOpenBmcBase, SIGINT, stopAsioRunLoop);
    registerSignalHandler(ipmi::prioOpenBmcBase, SIGTERM, stopAsioRunLoop);

    io->run();

    // destroy all the IPMI handlers so the providers can unload safely
    ipmi::handlerMap.clear();
    ipmi::groupHandlerMap.clear();
    ipmi::oemHandlerMap.clear();
    ipmi::filterList.clear();
    // unload the provider libraries
    providers.clear();

    return 0;
}
