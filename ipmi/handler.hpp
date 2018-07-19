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
#include <ipmi/ipmi-api.hpp>
#include <ipmi/message.hpp>
#include <memory>
#include <phosphor-logging/log.hpp>

#include <tuple>
#include <utility>


#ifdef ALLOW_DEPRECATED_API
#include <host-ipmid/ipmid-api.h>
#endif /* ALLOW_DEPRECATED_API */




namespace ipmi
{

template<typename... Args>
static inline message::Response::ptr errorResponse(
    message::Request::ptr request, ipmi::Cc cc, Args&&... args)
{
  message::Response::ptr response = request->makeResponse();
  auto payload = std::make_tuple(cc, args...);
  response->pack(payload);
  return response;
}
static inline message::Response::ptr errorResponse(
    message::Request::ptr request, ipmi::Cc cc)
{
  message::Response::ptr response = request->makeResponse();
  response->pack(cc);
  return response;
}

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
    message::Response::ptr response;
    try
    {
      response = executeCallback<Handler>(request);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
      response = errorResponse(request, ccUnspecifiedError);
      phosphor::logging::log<phosphor::logging::level::ERR>(
          "Handler failed to catch sdbus exception",
          phosphor::logging::entry("EXCEPTION=", e.what()));
    }
    catch (...)
    {
      response = errorResponse(request, ccUnspecifiedError);
      std::cerr << "Handler failed to catch unexpected exception\n";
    }
    return response;
  }

 private:
  Handler handler_;

  template <typename T>
  std::enable_if_t<!std::is_same<
    boost::callable_traits::args_t<T>,
    boost::callable_traits::args_t<LegacyHandler_t>
      >::value, message::Response::ptr>
  executeCallback(message::Request::ptr request)
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
      response->cc = unpackError;
      return response;
    }
    // execute the registered callback function and get the ipmi::RspType
    auto result = std::apply(handler_, inputArgs);

    response->cc = std::get<0>(result);
    auto payload = std::get<1>(result);
    // check for optional payload
    if (payload) {
      response->pack(*payload);
    }
    return response;
  }

#ifdef ALLOW_DEPRECATED_API
  /* specialization for legacy handler */
  template <typename T>
  std::enable_if_t<std::is_same<
    boost::callable_traits::args_t<T>,
    boost::callable_traits::args_t<LegacyHandler_t>
      >::value, message::Response::ptr>
  executeCallback(message::Request::ptr request)
  {
    auto response = request->makeResponse();
    size_t len = request->raw.size();
    // allocate a big response buffer here
    response->raw.resize(64*1024);

    auto ccRet = handler_(0, 0, request->raw.data(),
        response->raw.data(), &len, NULL);
    response->cc = ccRet;
    response->raw.resize(len);
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
