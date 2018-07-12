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
#include <algorithm>
#include <boost/callable_traits.hpp>
#include <cstdint>
#include <memory>
#include <tuple>
#include <utility>

#include <ipmi/ipmi-api.hpp>
#include <ipmi/message.hpp>


#ifdef ALLOW_DEPRECATED_API
/* FOR NOW UNTIL INTEGRATION */
// ----------------------------------------------------------------------------

/*
 * Specifies the minimum privilege level required to execute the command
 * This means the command can be executed at a given privilege level or higher
 * privilege level. Those commands which can be executed via system interface
 * only should use SYSTEM_INTERFACE
 */
enum CommandPrivilege {
  PRIVILEGE_CALLBACK = 0x01,
  PRIVILEGE_USER,
  PRIVILEGE_OPERATOR,
  PRIVILEGE_ADMIN,
  PRIVILEGE_OEM,
  SYSTEM_INTERFACE   = 0xFF,
};

typedef enum CommandPrivilege ipmi_cmd_privilege_t;
// IPMI Net Function number as specified by IPMI V2.0 spec.
// Example :
// NETFUN_APP      =   (0x06 << 2),
typedef unsigned char   ipmi_netfn_t;

// IPMI Command for a Net Function number as specified by IPMI V2.0 spec.
typedef unsigned char   ipmi_cmd_t;

// Buffer containing data from sender of netfn and command as part of request
typedef void*           ipmi_request_t;

// This is the response buffer that the provider of [netfn,cmd] will send back
// to the caller. Provider will allocate the memory inside the handler and then
// will do a memcpy to this response buffer and also will set the data size
// parameter to the size of the buffer.
// EXAMPLE :
// unsigned char str[] = {0x00, 0x01, 0xFE, 0xFF, 0x0A, 0x01};
// *data_len = 6;
// memcpy(response, &str, *data_len);
typedef void*           ipmi_response_t;

// This buffer contains any *user specific* data that is of interest only to the
// plugin. For a ipmi function router, this data is opaque. At the time of
// registering the plugin handlers, plugin may optionally allocate a memory and
// fill in whatever needed that will be of help during the actual handling of
// command. IPMID will just pass the netfn, cmd and also this data to plugins
// during the command handler invocation.
typedef void*           ipmi_context_t;

// Length of request / response buffer depending on whether the data is a
// request or a response from a plugin handler.
typedef size_t*   ipmi_data_len_t;

// Plugin function return the status code
typedef unsigned char ipmi_ret_t;

typedef ipmi_ret_t (*ipmid_callback_t)(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                       ipmi_response_t, ipmi_data_len_t, ipmi_context_t);

// ----------------------------------------------------------------------------
/* END NOW UNTIL INTEGRATION */
#endif /* ALLOW_DEPRECATED_API */




namespace ipmi
{

namespace details
{

/**
 * @brief Handler base class for dealing with IPMI request/response
 *
 * The subclasses are all templated so they can provide access to any type of
 * command callback functions.
 */
class HandlerBase
{
 public:
  using ptr = std::shared_ptr<HandlerBase>;

  virtual message::Response::ptr call(message::Request::ptr request) = 0;
};

/* handler
 *
 * this is the base template that ipmi handlers will resolve into
 */
template <typename Handler>
class IpmiHandler : public HandlerBase
{
 using LegacyHandler_t =
      ipmi_ret_t(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
          ipmi_response_t, ipmi_data_len_t, ipmi_context_t);
 public:
  IpmiHandler(const Handler&& handler)
    : handler_(std::move(handler))
  {
  }
#ifdef ALLOW_DEPRECATED_API
  IpmiHandler(const ipmid_callback_t handler)
    : handler_(handler)
  {
  }
#endif /* ALLOW_DEPRECATED_API */

  message::Response::ptr call(message::Request::ptr request) override
  {
    return executeCallback<Handler>(request);
  }

 private:
  Handler handler_;

  template <typename T>
  std::enable_if_t<!std::is_same<
    boost::callable_traits::args_t<T>,
    boost::callable_traits::args_t<LegacyHandler_t>
      >::value, message::Response::ptr> executeCallback(message::Request::ptr request)
  {
    // std::cerr << __FUNCTION__ << ':' << __LINE__ << '\n';
    auto response = request->makeResponse();

    // boost::callable_traits::args_t
    using callbackSig = boost::callable_traits::args_t<Handler>;
    using inputArgsType = typename utility::decay_tuple<callbackSig>::type;
    inputArgsType inputArgs;
    ipmi::Cc unpackError = request->unpack(inputArgs);
    if (ipmi::ccSuccess != unpackError)
    {
      response->pack(unpackError);
      return response;
    }
    auto result = std::apply(handler_, inputArgs);
    auto payload = std::get<1>(result);
    // check for optional payload
    if (payload) {
      auto repack = std::tuple_cat(std::make_tuple(std::get<0>(result)), *payload);
      response->pack(repack);
    }
    else
    {
      auto errorResponse = std::get<0>(result);
      response->pack(errorResponse);
    }
    return response;
  }

#ifdef ALLOW_DEPRECATED_API
  /* specialization for legacy handler */
  template <typename T>
  std::enable_if_t<std::is_same<
    boost::callable_traits::args_t<T>,
    boost::callable_traits::args_t<LegacyHandler_t>
      >::value, message::Response::ptr> executeCallback(message::Request::ptr request)
  {
    auto response = request->makeResponse();
    size_t len = request->raw.size();
    // allocate a big response buffer here
    response->raw.resize(64*1024);

    auto ccRet = handler_(0, 0, request->raw.data(),
        response->raw.data() + 1, &len, NULL);
    response->raw[0] = ccRet;
    response->raw.resize(1 + len);
    return response;
  }
#endif /* ALLOW_DEPRECATED_API */

};

template<typename Handler>
static inline auto makeHandler(const Handler&& handler)
{
  HandlerBase::ptr ptr(
      new IpmiHandler<decltype(handler)>(std::forward<Handler>(handler))
    );
  return ptr;
}

#ifdef ALLOW_DEPRECATED_API
static inline auto makeHandler(const ipmid_callback_t handler)
{
  HandlerBase::ptr ptr(
      new IpmiHandler<decltype(handler)>(handler)
    );
  return ptr;
}
#endif /* ALLOW_DEPRECATED_API */

} // namespace details

} // namespace ipmi
