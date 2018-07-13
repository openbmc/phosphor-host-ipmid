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
#include <algorithm>
#include <boost/callable_traits.hpp>
#include <cstdint>
#include <dlfcn.h>

#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace std {
  // splice experimental::filesystem into std
  namespace filesystem = std::experimental::filesystem;
}
#else
#  error filesystem not available
#endif

#include <iostream>
#include <ipmi/ipmi-api.hpp>
#include <ipmi/message/types.hpp>
#include <ipmi/message.hpp>
#include <ipmi/handler.hpp>
#include <list>
#include <map>
#include <memory>

#if __has_include(<optional>)
#include <optional>
#elif __has_include(<experimental/optional>)
#include <experimental/optional>
namespace std {
  // splice experimental::optional into std
  using std::experimental::optional;
  using std::experimental::make_optional;
  using std::experimental::nullopt;
}
#else
#  error optional not available
#endif

#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <tuple>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

using namespace phosphor::logging;

// to make sdbusplus a header-only lib
sdbusplus::SdBusImpl sdbus_impl;

// Global timer for network changes
std::unique_ptr<phosphor::ipmi::Timer> networkTimer = nullptr;

// IPMI Spec, shared Reservation ID.
unsigned short g_sel_reserve = 0xFFFF;

unsigned short get_sel_reserve_id(void)
{
  return g_sel_reserve;
}

sd_bus *bus;
sd_event *events = nullptr;
extern "C"
sd_event *ipmid_get_sd_event_connection(void)
{
  return events;
}
extern "C"
sd_bus *ipmid_get_sd_bus_connection(void)
{
  return bus;
}

namespace ipmi
{
namespace impl
{

static uint64_t id = 42;

uint64_t nextId()
{
  return ++id;
}

using HandlerTuple = std::tuple<
  int, /* prio */
  Privilege,
  details::HandlerBase::ptr, /* handler */
  std::any /* ctx */
>;

// TODO: these should probably be std::unordered_map instead of std::map
//       but that requires setting up the hashing of keys....

/* map to handle standard registered commands */
static std::map<
  std::pair<NetFn, Cmd>, /* key is NetFn/Cmd */
  HandlerTuple
  > handlerMap;

/* special map for decoding Group registered commands (NetFn 2Ch) */
static std::map<
  std::pair<Group, Cmd>, /* key is Group/Cmd (NetFn is 2Ch) */
  HandlerTuple
  > groupHandlerMap;

/* special map for decoding OEM registered commands (NetFn 2Eh) */
static std::map<
  std::pair<Iana, Cmd>, /* key is Iana/Cmd (NetFn is 2Eh) */
  HandlerTuple
  > oemHandlerMap;

using FilterTuple = std::tuple<
  int, /* prio */
  details::FilterBase::ptr, /* filter */
  std::any /* ctx */
>;

/* list to hold all registered ipmi command filters */
static std::list<FilterTuple> filterList;


/* common function to register all standard IPMI handlers */
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx)
{
  // check for valid NetFn: even; 00-0Ch, 30-3Eh
  if (netFn & 1 ||
      (netFn > netFnTransport && netFn < netFnGroup) ||
      netFn > netFnOemEight)
  {
    // TODO: log an error, throw, what?
    return;
  }

  // create key and value for this handler
  std::pair<NetFn, Cmd> netFnCmd(netFn, cmd);
  HandlerTuple item(prio, priv, handler, ctx);

  // consult the handler map and look for a match
  auto& mapCmd = handlerMap[netFnCmd];
  if (!std::get<details::HandlerBase::ptr>(mapCmd))
  {
    mapCmd = item;
  }
  else if (std::get<0>(mapCmd) <= prio)
  {
    mapCmd = item;
  }
}

/* common function to register all Group IPMI handlers */
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx)
{
  // create key and value for this handler
  std::pair<Group, Cmd> netFnCmd(group, cmd);
  HandlerTuple item(prio, priv, handler, ctx);

  // consult the handler map and look for a match
  auto& mapCmd = groupHandlerMap[netFnCmd];
  if (!std::get<details::HandlerBase::ptr>(mapCmd))
  {
    mapCmd = item;
  }
  else if (std::get<0>(mapCmd) <= prio)
  {
    mapCmd = item;
  }
}

/* common function to register all OEM IPMI handlers */
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx)
{
  // create key and value for this handler
  std::pair<Iana, Cmd> netFnCmd(iana, cmd);
  HandlerTuple item(prio, priv, handler, ctx);

  // consult the handler map and look for a match
  auto& mapCmd = oemHandlerMap[netFnCmd];
  if (!std::get<details::HandlerBase::ptr>(mapCmd))
  {
    mapCmd = item;
  }
  else if (std::get<0>(mapCmd) <= prio)
  {
    mapCmd = item;
  }
}

/* common function to register all standard IPMI handlers */
void registerFilter(int prio, details::FilterBase::ptr filter, std::any& ctx)
{
  FilterTuple item(prio, filter, ctx);

  // walk the list and put it in the right place
  auto i = filterList.begin();
  for (; i != filterList.end() && std::get<int>(*i) > prio; i++);
  filterList.insert(i, item);
}

message::Response::ptr executeIpmiGroupCommand(message::Request::ptr request)
{
  // Get the cmd from contextInfo, look up the group/cmd handler
  Group group;
  if (0 != request->unpack(group))
  {
    return errorResponse(request, ccReqDataLenInvalid);
  }
  // The handler will need to unpack group as well; we just need it for lookup
  request->reset();
  Cmd cmd = request->ctx->cmd;
  std::pair<Group, Cmd> key(group, cmd);
  auto cmdIter = groupHandlerMap.find(key);
  if (cmdIter != groupHandlerMap.end())
  {
    HandlerTuple& chosen = cmdIter->second;
    if (request->ctx->priv < std::get<Privilege>(chosen))
    {
      return errorResponse(request, ccReqDataLenInvalid, group);
    }
    return std::get<details::HandlerBase::ptr>(chosen)->call(request);
  }
  else
  {
    std::pair<Group, Cmd> wildcard(group, cmdWildcard);
    cmdIter = groupHandlerMap.find(wildcard);
    if (cmdIter != groupHandlerMap.end())
    {
      HandlerTuple& chosen = cmdIter->second;
      if (request->ctx->priv < std::get<Privilege>(chosen))
      {
        return errorResponse(request, ccInsufficientPrivilege, group);
      }
      return std::get<details::HandlerBase::ptr>(chosen)->call(request);
    }
  }
  return errorResponse(request, ccInvalidCommand, group);
}

message::Response::ptr executeIpmiOemCommand(message::Request::ptr request)
{
  Iana iana;
  if (0 != request->unpack(iana))
  {
      return errorResponse(request, ccReqDataLenInvalid);
  }
  request->reset();
  Cmd cmd = request->ctx->cmd;
  std::pair<Iana, Cmd> key(iana, cmd);
  auto cmdIter = oemHandlerMap.find(key);
  if (cmdIter != oemHandlerMap.end())
  {
    HandlerTuple& chosen = cmdIter->second;
    if (request->ctx->priv < std::get<Privilege>(chosen))
    {
      return errorResponse(request, ccInsufficientPrivilege, iana);
    }
    return std::get<details::HandlerBase::ptr>(chosen)->call(request);
  }
  else
  {
    std::pair<Iana, Cmd> wildcard(iana, cmdWildcard);
    cmdIter = oemHandlerMap.find(wildcard);
    if (cmdIter != oemHandlerMap.end())
    {
      HandlerTuple& chosen = cmdIter->second;
      if (request->ctx->priv < std::get<Privilege>(chosen))
      {
        return errorResponse(request, ccInsufficientPrivilege, iana);
      }
      return std::get<details::HandlerBase::ptr>(chosen)->call(request);
    }
  }
  return errorResponse(request, ccInvalidCommand, iana);
}

message::Response::ptr filterIpmiCommand(message::Request::ptr request)
{
  // pass the command through the filter mechanism
  // This can be the firmware firewall or any OEM mechanism like
  // whitelist filtering based on operational mode
  for (auto& item : filterList)
  {
    auto& filter = std::get<1>(item);
    // auto& ctx = std::get<2>(item);
    ipmi::Cc cc = filter->call(request);
    if (ipmi::ccSuccess != cc)
    {
      return errorResponse(request, cc);
    }
  }
  return message::Response::ptr();
}

message::Response::ptr executeIpmiCommand(message::Request::ptr request)
{
  // the command has already passed through filter; execute it
  NetFn netFn = request->ctx->netFn;
  Cmd cmd = request->ctx->cmd;
  if (netFnGroup == netFn)
  {
    return executeIpmiGroupCommand(request);
  }
  else if (netFnOem == netFn)
  {
    return executeIpmiOemCommand(request);
  }
  /* normal IPMI command */
  std::pair<NetFn, Cmd> key(netFn, cmd);
  auto cmdIter = handlerMap.find(key);
  if (cmdIter != handlerMap.end())
  {
    HandlerTuple& chosen = cmdIter->second;
    if (request->ctx->priv < std::get<Privilege>(chosen))
    {
      return errorResponse(request, ccInsufficientPrivilege);
    }
    return std::get<details::HandlerBase::ptr>(chosen)->call(request);
  }
  else
  {
    std::pair<NetFn, Cmd> wildcard(netFn, cmdWildcard);
    cmdIter = handlerMap.find(wildcard);
    if (cmdIter != handlerMap.end())
    {
      HandlerTuple& chosen = cmdIter->second;
      if (request->ctx->priv < std::get<Privilege>(chosen))
      {
        return errorResponse(request, ccInsufficientPrivilege);
      }
      return std::get<details::HandlerBase::ptr>(chosen)->call(request);
    }
  }
  return errorResponse(request, ccInvalidCommand);
}

} // namespace impl

/* called from sdbus async server context */
auto executionEntry(uint8_t seq, NetFn netFn, uint8_t lun, Cmd cmd,
    std::vector<uint8_t>& data)
{
  auto ctx = std::make_shared<ipmi::Context>(
      netFn, cmd, 0, 0, ipmi::privilegeAdmin);
  auto request = std::make_shared<ipmi::message::Request>(ctx, data,
      ipmi::impl::nextId());
  auto response = ipmi::impl::filterIpmiCommand(request);
  // an empty response means the command was not filtered
  if (!response)
  {
    response = ipmi::impl::executeIpmiCommand(request);
  }

  // Responses in IPMI require a bit set.  So there ya go...
  netFn |= 0x01;
  return std::make_tuple(seq, netFn, lun, cmd, response->cc, response->raw);
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

    IpmiProvider() = delete;
    IpmiProvider(const IpmiProvider&) = delete;
    IpmiProvider& operator=(const IpmiProvider&) = delete;
    IpmiProvider(IpmiProvider&&) = default;
    IpmiProvider& operator=(IpmiProvider&&) = default;

    /** @brief dlopen a shared object file by path
     *  @param[in]  filename - path of shared object to open
     */
    IpmiProvider(const char *fname)
    {
      std::cerr << "opening " << fname << '\n';
      addr = dlopen(fname, RTLD_NOW);
      if (!isOpen())
      {
        log<level::ERR>("ERROR opening",
                        entry("HANDLER=%s", fname),
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
std::vector<IpmiProvider> loadProviders(const fs::path& ipmiLibsPath)
{
  std::vector<fs::path> libs;
  for (auto& libPath: fs::directory_iterator(ipmiLibsPath))
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

  std::vector<IpmiProvider> handles;
  for (auto& lib : libs)
  {
#ifdef __IPMI_DEBUG__
    log<level::DEBUG>("Registering handler",
                      entry("HANDLER=%s", lib.c_str()));
#endif
    handles.emplace_back(lib.c_str());
  }
  return handles;
}

} // namespace ipmi

#ifdef ALLOW_DEPRECATED_API
/* legacy registration */
void ipmi_register_callback(ipmi_netfn_t netFn,
        ipmi_cmd_t cmd, ipmi_context_t context,
        ipmid_callback_t handler, ipmi_cmd_privilege_t priv)
{
  auto h = ipmi::details::makeHandler(handler);
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
  ipmi::impl::registerHandler(ipmi::prioOpenBmcBase, netFn, cmd,
      realPriv, h, ctx);
}

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

/* legacy alternative to executionEntry */
void handleLegacyIpmiCommand(sdbusplus::message::message& m)
{
  unsigned char seq, netFn, lun, cmd;
  std::vector<uint8_t> data;

  m.read(seq, netFn, lun, cmd, data);

  auto ctx = std::make_shared<ipmi::Context>(
      netFn, cmd, 0, 0, ipmi::privilegeAdmin);
  auto request = std::make_shared<ipmi::message::Request>(ctx, data,
      ipmi::impl::nextId());

  auto response = ipmi::impl::filterIpmiCommand(request);
  // an empty response means the command was not filtered
  if (!response)
  {
    response = ipmi::impl::executeIpmiCommand(request);
  }

  // Responses in IPMI require a bit set.  So there ya go...
  netFn |= 0x01;

  const char *dest, *path;
  constexpr const char * DBUS_INTF = "org.openbmc.HostIpmi";

  dest = m.get_sender();
  path = m.get_path();
  sdbusp->async_method_call([](boost::system::error_code ec){},
      dest, path, DBUS_INTF, "sendMessage",
      seq, netFn, lun, cmd, response->cc, response->raw);
}

#endif /* ALLOW_DEPRECATED_API */

int main(int argc, char *argv[])
{
  std::cerr << "ipmid-new\n";

  // Connect to system bus
  io = std::make_shared<boost::asio::io_service>();
  if (argc > 1 && std::string(argv[1]) == "-session")
  {
    std::cerr << "attaching to session bus\n";
    sd_bus_open_user(&bus);
  }
  else
  {
    sd_bus_open_system(&bus);
  }
  sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus);

  // Register all command providers and filters
  auto handles = ipmi::loadProviders(HOST_IPMI_LIB_PATH);

  sdbusp->request_name("xyz.openbmc_project.IPMI");

  // Add bindings for inbound IPMI requests
  auto server = sdbusplus::asio::object_server(sdbusp);
  auto iface = server.add_interface("/xyz/openbmc_project/IPMI",
      "xyz.openbmc_project.ipmi.server");
  iface->register_method("execute", ipmi::executionEntry);
  iface->initialize();

#ifdef ALLOW_DEPRECATED_API
  // listen on deprecated signal interface for kcs/bt commands
  constexpr const char * FILTER =
    "type='signal',interface='org.openbmc.HostIpmi',member='ReceivedMessage'";
  sdbusplus::bus::match::match
    oldIpmiInterface(*sdbusp, FILTER, handleLegacyIpmiCommand);
#endif /* ALLOW_DEPRECATED_API */

  io->run();

  // This avoids a warning about unused variables
  handles.clear();
  return 0;
}

