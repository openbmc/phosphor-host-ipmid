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
#pragma once
#if __has_include(<any>)
#include <any>
#elif __has_include(<experimental/any>)
#include <experimental/any>
namespace std {
  // splice experimental::any into std
  using std::experimental::any;
}
#else
#  error any not available
#endif
#include <ipmi/ipmi-api.hpp>
#include <ipmi/handler.hpp>
#include <ipmi/filter.hpp>

namespace ipmi
{


namespace impl
{

// IPMI command handler registration implementation
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx);
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx);
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
    details::HandlerBase::ptr handler, std::any& ctx);

// IPMI command filter registration implementation
void registerFilter(int prio, details::FilterBase::ptr filter, std::any& ctx);

} // namespace impl

template <typename Handler>
void registerHandler(int prio, NetFn netFn, Cmd cmd,
    Privilege priv, Handler&& handler)
{
  auto h = ipmi::details::makeHandler(handler);
  // use an empty std::any for context since none was passed in
  std::any empty;
  impl::registerHandler(prio, netFn, cmd, priv, h, empty);
}

template <typename Handler, typename Context>
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
    Handler&& handler, Context& ctx)
{
  auto h = ipmi::details::makeHandler(handler);
  // add in a std::any(ctx) to the mix
  impl::registerHandler(prio, netFn, cmd, priv, h, std::any(ctx));
}

/* From IPMI 2.0 spec Network Function Codes Table (Row 2Ch):
    The first data byte position in requests and respo nses under this network
    function identifies the defining body that specifies command functionality.
    Software assumes that the command and completion code field positions will
    hold command and completion code values.

    The following values are used to ident ify the defining body:
    00h PICMG - PCI Industrial Computer Manufacturer’s Group.  ( www.picmg.com )
    01h DMTF Pre-OS Working Group ASF Specification ( www.dmtf.org )
    02h Server System Infrastructure (SSI) Forum ( www.ssiforum.org )
    03h VITA Standards Organization (VSO) (www.vita.com)
    DCh DCMI Specifications ( www.intel.com/go/dcmi )
    all other Reserved

    When this network function is used, the ID for the defining body occupies
    the first data byte in a request, and the second data byte (following the
    completion code) in a response.
 */
template <typename Handler>
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
    Handler&& handler)
{
  auto h = ipmi::details::makeHandler(handler);
  // use an empty std::any for context since none was passed in
  std::any empty;
  impl::registerGroupHandler(prio, group, cmd, priv, h, empty);
}

template <typename Handler, typename Context>
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
    Handler&& handler, Context& ctx)
{
  auto h = ipmi::details::makeHandler(handler);
  // add in a std::any(ctx) to the mix
  impl::registerGroupHandler(prio, group, cmd, priv, h, std::any(ctx));
}

/* From IPMI spec Network Function Codes Table (Row 2Eh):
    The first three data bytes of requests and responses under this network
    function explicitly identify the OEM or non -IPMI group that specifies the
    command functionality. While the OEM or non -IPMI group defines the
    functional semantics for the cmd and remaining data fields, the cmd field
    is required to hold the same value in requests and responses for a given
    operation in order to be supported under the IPMI message handling and
    transport mechanisms.

    When this network function is used, the IANA Enterprise Number for the
    defining body occupies the first three data bytes in a request, and the
    first three data bytes following the completion code position in a
    response.
 */
template <typename Handler>
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
    Handler&& handler)
{
  auto h = ipmi::details::makeHandler(handler);
  // use an empty std::any for context since none was passed in
  std::any empty;
  impl::registerOemHandler(prio, iana, cmd, priv, h, empty);
}

template <typename Handler, typename Context>
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
    Handler&& handler, Context& ctx)
{
  auto h = ipmi::details::makeHandler(handler);
  // add in a std::any(ctx) to the mix
  impl::registerOemHandler(prio, iana, cmd, priv, h, std::any(ctx));
}

template <typename Filter>
void registerFilter(int prio, Filter&& filter)
{
  auto f = ipmi::details::makeFilter(filter);
  // use an empty std::any for context since none was passed in
  std::any empty;
  impl::registerFilter(prio, f, empty);
}

template <typename Filter, typename Context>
void registerFilter(int prio, Filter&& filter, Context& ctx)
{
  auto f = ipmi::details::makeFilter(filter);
  // add in a std::any(ctx) to the mix
  impl::registerFilter(prio, f, std::any(ctx));
}
} // namespace ipmi

#ifdef ALLOW_DEPRECATED_API
/* TODO: deprecated function: print warning once no more *internal*
 *       IPMI command handlers use this; delete it a year after that.
 */
// [[deprecated("Use ipmi::registerHandler() instead")]]
extern "C"
void ipmi_register_callback(ipmi_netfn_t netFn,
        ipmi_cmd_t cmd, ipmi_context_t context,
        ipmid_callback_t handler, ipmi_cmd_privilege_t priv);

#endif /* ALLOW_DEPRECATED_API */


