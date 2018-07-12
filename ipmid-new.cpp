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
#include <cstdint>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

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

#include <boost/callable_traits.hpp>
#include <ipmi/ipmi-api.hpp>
#include <ipmi/message/types.hpp>
#include <ipmi/message.hpp>
#include <ipmi/handler.hpp>

namespace ipmi
{
namespace impl
{

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
  std::list<HandlerTuple>
  > handlerMap;

/* special map for decoding Group registered commands (NetFn 2Ch) */
static std::map<
  std::pair<Group, Cmd>, /* key is Group/Cmd (NetFn is 2Ch) */
  std::list<HandlerTuple>
  > groupHandlerMap;

/* special map for decoding OEM registered commands (NetFn 2Eh) */
static std::map<
  std::pair<Iana, Cmd>, /* key is Iana/Cmd (NetFn is 2Eh) */
  std::list<HandlerTuple>
  > oemHandlerMap;


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
  auto& cmdList = handlerMap[netFnCmd];
  if (cmdList.empty())
  {
    cmdList.push_front(item);
  }
  else
  {
    auto pos = cmdList.begin();
    // walk the the netfn/cmd priority list and insert at the right place
    for (; pos != cmdList.end() && std::get<0>(*pos) < prio; pos++);
    cmdList.insert(pos, item);
  }
}

/* common function to register all Group IPMI handlers */
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx)
{
  // TODO: main prog should make sure that 2Ch/wildcard is registered for groupIpmiHandler

  // create key and value for this handler
  std::pair<Group, Cmd> netFnCmd(group, cmd);
  HandlerTuple item(prio, priv, handler, ctx);

  // consult the handler map and look for a match
  auto& cmdList = groupHandlerMap[netFnCmd];
  if (cmdList.empty())
  {
    cmdList.push_front(item);
  }
  else
  {
    auto pos = cmdList.begin();
    // walk the the group/cmd priority list and insert at the right place
    for (; pos != cmdList.end() && std::get<0>(*pos) < prio; pos++);
    cmdList.insert(pos, item);
  }
}

/* common function to register all OEM IPMI handlers */
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx)
{
  // TODO: main prog should make sure that 2Eh/wildcard is registered for oemIpmiHandler

  // create key and value for this handler
  std::pair<Iana, Cmd> netFnCmd(iana, cmd);
  HandlerTuple item(prio, priv, handler, ctx);

  // consult the handler map and look for a match
  auto& cmdList = oemHandlerMap[netFnCmd];
  if (cmdList.empty())
  {
    cmdList.push_front(item);
  }
  else
  {
    auto pos = cmdList.begin();
    // walk the the group/cmd priority list and insert at the right place
    for (; pos != cmdList.end() && std::get<0>(*pos) < prio; pos++);
    cmdList.insert(pos, item);
  }
}

// in static int handle_ipmi_command(...):
//   r = ipmi_netfn_router(netfn, cmd, (void *)request, (void *)response, &resplen);

// ipmi_ret_t ipmi_netfn_router(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
//                       ipmi_response_t response, ipmi_data_len_t data_len);
bool filterIpmiCommand(NetFn netFn, Cmd cmd,
    std::vector<uint8_t>& request /*, contextInfo */)
{
  // pass the command through the filter mechanism
  // This can be the firmware firewall or any OEM mechanism like
  // whitelist filtering based on operational mode
  return true;
}

template<typename... Args>
auto errorResponse(message::Request::ptr request, ipmi::Cc cc, Args&&... args)
{
  auto response = request->makeResponse();
  auto payload = std::make_tuple(cc, args...);
  response->pack(payload);
  return response;
}
auto errorResponse(message::Request::ptr request, ipmi::Cc cc)
{
  auto response = request->makeResponse();
  response->pack(cc);
  return response;
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
    HandlerTuple& chosen = cmdIter->second.front();
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
      HandlerTuple& chosen = cmdIter->second.front();
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
  /*
  std::cerr << "checking map for <" << iana << ',' << int(cmd) << ">\n";
  for (const auto& h : oemHandlerMap)
  {
    const auto& k = h.first;
    const auto& v = h.second;
    std::cerr << "map item <" << std::get<Iana>(k) << ',' << int(std::get<Cmd>(k)) << ">\n";
  }
  */
  auto cmdIter = oemHandlerMap.find(key);
  if (cmdIter != oemHandlerMap.end())
  {
    HandlerTuple& chosen = cmdIter->second.front();
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
      HandlerTuple& chosen = cmdIter->second.front();
      if (request->ctx->priv < std::get<Privilege>(chosen))
      {
        return errorResponse(request, ccInsufficientPrivilege, iana);
      }
      return std::get<details::HandlerBase::ptr>(chosen)->call(request);
    }
  }
  return errorResponse(request, ccInvalidCommand, iana);
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
    HandlerTuple& chosen = cmdIter->second.front();
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
      HandlerTuple& chosen = cmdIter->second.front();
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

} // namespace ipmi

#ifdef ALLOW_DEPRECATED_API
/* legacy registration */
void ipmi_register_callback(ipmi_netfn_t netfn,
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
  ipmi::impl::registerHandler(ipmi::prioOpenBmcBase, netfn, cmd,
      realPriv, h, ctx);
}

#endif /* ALLOW_DEPRECATED_API */

#define TEST 1

#ifdef TEST
/******************************************************************************
 * begin of test handlers
 *****************************************************************************/

auto ipmiGetDeviceId() ->
  ipmi::RspType<
    ipmi::Cc, // CC
    uint8_t,  // Device ID
    uint8_t,  // Device Revision
    uint8_t,  // Firmware Revision Major
    uint8_t,  // Firmware Revision minor
    uint8_t,  // IPMI version
    uint8_t,  // Additional device support
    uint8_t,  // MFG ID LSB
    uint8_t,  // MFG ID 2
    uint8_t,  // MFG ID MSB
    uint16_t, // Product ID
    uint32_t // AUX info
    >
{
  std::cerr << __FUNCTION__ << '\n';
  return ipmi::response(
      ipmi::ccSuccess,
      uint8_t(0x83),
      uint8_t(0x22),
      uint8_t(0x01),
      uint8_t(0x23),
      uint8_t(2),
      uint8_t(0xff),
      uint8_t(0x57),
      uint8_t(0x01),
      uint8_t(0x00),
      uint16_t(0x01b4),
      uint32_t(0x23a4b79)
      );
}

auto always_invalid() ->
  ipmi::RspType<ipmi::Cc>
{
  std::cerr << __PRETTY_FUNCTION__ << '\n';
  ipmi::Cc cc = ipmi::ccInvalidFieldRequest;
  return ipmi::response(cc);
}

auto sometimes_invalid(uint8_t invalid)
  -> ipmi::RspType<ipmi::Cc, uint8_t, uint8_t>
{
  std::cerr << __PRETTY_FUNCTION__ << ": invalid = " << int(invalid) << '\n';
  if (invalid)
  {
    ipmi::Cc cc = ipmi::ccInvalidFieldRequest;
    return ipmi::response(cc);
  }
  return ipmi::response(ipmi::ccSuccess, uint8_t(0x22), uint8_t(0x07));
}

auto print_values(uint16_t u16, const std::string& s,
    uint32_t u32, uint8_t u8, double d)
{
  std::cerr << __PRETTY_FUNCTION__ << '\n';
  std::cerr << std::hex
    << "u16 = " << u16
    << "\ns = (" << s.length() << ")'" << s
    << "'\nu32 = " << u32
    << "\nu8 = " << int(u8)
    << "\nd = " << d
    << "\n";
  // return std::make_tuple(uint8_t(0), 'a', uint8_t(0x9f), uint16_t(0xbeef),
  //        uint32_t(0xd00dfeed), double(2.71828182845904523536028747135));
  return ipmi::response(ipmi::ccSuccess, u16, s, u32, u8, d);
}

auto OemCustomCmd(uint24_t iana, uint8_t cmd, bool enabled, uint7_t other, std::bitset<5> fivr, std::bitset<3> three)
{
  std::cerr << __FUNCTION__ << "(uint24_t iana, uint8_t cmd, bit enabled, uint7_t other, bitset<5> fivr, bitset<3> three)\n";
  std::cerr << std::hex
    << "iana = " << iana
    << "\ncmd = " << int(cmd)
    << "\nenabled = " << enabled
    << "\nother = " << other
    << "\nfivr = " << fivr
    << "\nthree = " << three
    << "\n";
  return ipmi::response(ipmi::ccSuccess, 'a', uint4_t(0x9), uint2_t(3), bit(1), true, uint16_t(0xbeef),
          uint32_t(0xd00dfeed), double(2.71828182845904523536028747135), fivr, three);
}

ipmi_ret_t ipmiLegacyGetDeviceID(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
    ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t len, ipmi_context_t ctx)
{
  std::cerr << __PRETTY_FUNCTION__ << '\n';
  std::array<uint8_t, 15> id = {{
      0x83, 0x22, 0x01, 0x23, 0x02, 0xff, 0x57, 0x01,
      0x00, 0xb4, 0x01, 0x79, 0x4b, 0x3a, 0x02 }};
  if (*len > 0)
  {
    return 0xcc;
  }
  std::copy(id.begin(), id.end(), reinterpret_cast<uint8_t*>(response));
  *len = id.size();
  return 0;
}
/******************************************************************************
 * end of test handlers
 *****************************************************************************/

int main()
{
  // void registerHandler(int prio, NetFn netFn, Cmd cmd,
  //     Privilege priv, Handler&& handler)
  uint64_t id = 42;
  ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne, 1,
      ipmi::privilegeAdmin, always_invalid);
  ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne, 2,
      ipmi::privilegeAdmin, sometimes_invalid);
  ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne, 3,
      ipmi::privilegeAdmin, print_values);
  ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne, 4,
      ipmi::privilegeAdmin, ipmiGetDeviceId);
  ipmi_register_callback(0x30, 5, NULL, &ipmiLegacyGetDeviceID, PRIVILEGE_ADMIN);
  ipmi::registerOemHandler(ipmi::prioOpenBmcBase, 0x570100, 6,
      ipmi::privilegeAdmin, OemCustomCmd);

  using bytes = std::vector<uint8_t>;
  std::vector<
    std::tuple<
      std::string,            /* test name */
      ipmi::NetFn,            /* NetFn to test */
      ipmi::Cmd,              /* Cmd to test */
      bytes,                  /* input */
      bytes                   /* expected output (including CC) */
      >
    > tests;
  tests.emplace_back(std::make_tuple(
        "always_invalid",
        ipmi::netFnOemOne, 1,
        bytes({0}),
        bytes({ipmi::ccReqDataLenInvalid})
        ));
  tests.emplace_back(std::make_tuple(
        "always_invalid",
        ipmi::netFnOemOne, 1,
        bytes(),
        bytes({ipmi::ccInvalidFieldRequest})
        ));
  tests.emplace_back(std::make_tuple(
        "sometimes_invalid",
        ipmi::netFnOemOne, 2,
        bytes({0}),
        bytes({ipmi::ccSuccess, 0x22, 0x07})
        ));
  tests.emplace_back(std::make_tuple(
        "sometimes_invalid",
        ipmi::netFnOemOne, 2,
        bytes({1}),
        bytes({ipmi::ccInvalidFieldRequest})
        ));
  tests.emplace_back(std::make_tuple(
        "print_values",
        ipmi::netFnOemOne, 3,
        bytes({ 0x0d, 0xf0, 8, 'A', 'a', 'r', 'd', 'v', 'a', 'r', 'K', 0xef,
          0xbe, 0xad, 0xde, 0x42, 0x18, 0x2d, 0x44, 0x54, 0xfb, 0x21, 0x09,
          0x40 }),
        bytes({ ipmi::ccSuccess, 0x0d, 0xf0, 8, 'A', 'a', 'r', 'd', 'v', 'a',
          'r', 'K', 0xef, 0xbe, 0xad, 0xde, 0x42, 0x18, 0x2d, 0x44, 0x54, 0xfb,
          0x21, 0x09, 0x40 })
        ));
  tests.emplace_back(std::make_tuple(
        "ipmiGetDeviceId",
        ipmi::netFnOemOne, 4,
        bytes(),
        bytes({ ipmi::ccSuccess, 0x83, 0x22, 0x01, 0x23, 0x02, 0xff, 0x57,
          0x01, 0x00, 0xb4, 0x01, 0x79, 0x4b, 0x3a, 0x02 })
        ));
  tests.emplace_back(std::make_tuple(
        "ipmiLegacyGetDeviceID",
        ipmi::netFnOemOne, 5,
        bytes(),
        bytes({ ipmi::ccSuccess, 0x83, 0x22, 0x01, 0x23, 0x02, 0xff, 0x57,
          0x01, 0x00, 0xb4, 0x01, 0x79, 0x4b, 0x3a, 0x02 })
        ));
  tests.emplace_back(std::make_tuple(
        "OemCustomCmd",
        ipmi::netFnOem, 6,
        bytes({ 0x57, 0x01, 0x00, 0x37, 0xea, 0x2b }),
        bytes({ ipmi::ccSuccess, 0x61, 0x9f, 0xef, 0xbe, 0xed, 0xfe, 0x0d,
          0xd0, 0x69, 0x57, 0x14, 0x8b, 0x0a, 0xbf, 0x05, 0x40, 0x2b })
        ));

  int success = 0;
  std::cerr << std::hex;
  for (auto& test : tests)
  {
    auto ctx = std::make_shared<ipmi::Context>(
        std::get<1>(test), std::get<2>(test), 0, 0, ipmi::privilegeAdmin);
    auto request = std::make_shared<ipmi::message::Request>(ctx, std::get<3>(test), id++);
    auto response = ipmi::impl::executeIpmiCommand(request);
    const auto& out = std::get<4>(test);
    if (!std::equal(out.begin(), out.end(),
          response->raw.begin(), response->raw.end()))
    {
      std::cerr << std::get<0>(test) << " result does not match expected\n";
      success++;
    }
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
  }

  return success;
}
#endif /* TEST */
