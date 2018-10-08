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
#include <boost/asio/spawn.hpp>
#include <boost/callable_traits.hpp>
#include <cstdint>
#include <exception>
#include <ipmi/ipmi-api.hpp>
#include <ipmi/message.hpp>
#include <memory>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <tuple>
#include <utility>

#ifdef ALLOW_DEPRECATED_API
#include <host-ipmid/ipmid-api.h>

#include <host-ipmid/oemrouter.hpp>
#endif /* ALLOW_DEPRECATED_API */

namespace ipmi
{

template <typename... Args>
static inline message::Response::ptr
    errorResponse(message::Request::ptr request, ipmi::Cc cc, Args&&... args)
{
    message::Response::ptr response = request->makeResponse();
    auto payload = std::make_tuple(cc, args...);
    response->pack(payload);
    return response;
}
static inline message::Response::ptr
    errorResponse(message::Request::ptr request, ipmi::Cc cc)
{
    message::Response::ptr response = request->makeResponse();
    response->pack(cc);
    return response;
}

/*
// template to help extract a tuple of arg types into a std::function type
template <typename RetType, template <typename...> typename Container,
          typename... Args>
struct FunctionHelper;

template <typename RetType, template <typename...> typename Container,
          typename... Args>
struct FunctionHelper<RetType, Container<Args...>>
{
    using type = std::function<RetType(Args...)>;
};
*/
/**
 * @brief Handler base class for dealing with IPMI request/response
 *
 * The subclasses are all templated so they can provide access to any type
 * of command callback functions.
 */
class HandlerBase
{
  public:
    using ptr = std::shared_ptr<HandlerBase>;

    message::Response::ptr call(message::Request::ptr request)
    {
        message::Response::ptr response;
        try
        {
            response = executeCallback(request);
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
            std::exception_ptr eptr = std::current_exception();
            // turn the exception_ptr into a standard exception
            try
            {
                std::rethrow_exception(eptr);
            }
            catch (std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Handler failed to catch unexpected exception",
                    phosphor::logging::entry("EXCEPTION=", e.what()));
            }
        }
        return response;
    }

  private:
    virtual message::Response::ptr
        executeCallback(message::Request::ptr request) = 0;
};

/* handler
 *
 * this is the base template that ipmi handlers will resolve into
 */
template <typename Handler>
class IpmiHandler : public HandlerBase
{
  public:
    explicit IpmiHandler(Handler&& handler) : handler_(std::move(handler))
    {
    }

  private:
    Handler handler_;

    message::Response::ptr
        executeCallback(message::Request::ptr request) override
    {
        auto response = request->makeResponse();

        using CallbackSig = boost::callable_traits::args_t<Handler>;
        using InputArgsType = typename utility::DecayTuple<CallbackSig>::type;
        using UnpackArgsType = typename utility::StripFirstArgs<
            utility::NonIpmiArgsCount<InputArgsType>::size(),
            InputArgsType>::type;

        UnpackArgsType unpackArgs;
        ipmi::Cc unpackError = request->unpack(unpackArgs);
        if (ipmi::ccSuccess != unpackError)
        {
            response->cc = unpackError;
            return response;
        }
        std::optional<InputArgsType> inputArgs;
        if constexpr (std::tuple_size<InputArgsType>::value > 0)
        {
            if constexpr (std::is_same<std::tuple_element_t<0, InputArgsType>,
                                       boost::asio::yield_context>::value)
            {
                inputArgs.emplace(std::tuple_cat(
                    std::forward_as_tuple(*(request->ctx->yield)),
                    std::move(unpackArgs)));
            }
            else if constexpr (std::is_same<
                                   std::tuple_element_t<0, InputArgsType>,
                                   ipmi::Context::ptr>::value)
            {
                inputArgs.emplace(
                    std::tuple_cat(std::forward_as_tuple(request->ctx),
                                   std::move(unpackArgs)));
            }
            else if constexpr (std::is_same<
                                   std::tuple_element_t<0, InputArgsType>,
                                   ipmi::message::Request::ptr>::value)
            {
                inputArgs.emplace(std::tuple_cat(std::forward_as_tuple(request),
                                                 std::move(unpackArgs)));
            }
            else
            {
                inputArgs.emplace(std::move(unpackArgs));
            }
        }
        else
        {
            inputArgs = std::move(unpackArgs);
        }
        // execute the registered callback function and get the
        // ipmi::RspType
        auto result = std::apply(handler_, *inputArgs);

        response->cc = std::get<0>(result);
        auto payload = std::get<1>(result);
        // check for optional payload
        if (payload)
        {
            response->pack(*payload);
        }
        return response;
    }
};

#ifdef ALLOW_DEPRECATED_API
template <>
class IpmiHandler<ipmid_callback_t> : public HandlerBase
{
  public:
    explicit IpmiHandler(const ipmid_callback_t& handler) : handler_(handler)
    {
    }

  private:
    std::function<ipmi_ret_t(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                             ipmi_response_t, ipmi_data_len_t, ipmi_context_t)>
        handler_;

    /* specialization for legacy handler */
    message::Response::ptr
        executeCallback(message::Request::ptr request) override
    {
        auto response = request->makeResponse();
        size_t len = request->raw.size();
        // (re-)allocate a big request buffer here
        request->raw.resize(64 * 1024);
        // allocate a big response buffer here
        response->raw.resize(64 * 1024);

        auto ccRet =
            handler_(request->ctx->netFn, request->ctx->cmd,
                     request->raw.data(), response->raw.data(), &len, nullptr);
        response->cc = ccRet;
        response->raw.resize(len);
        return response;
    }
};
template <>
class IpmiHandler<oem::Handler> : public HandlerBase
{
  public:
    explicit IpmiHandler(const oem::Handler& handler) : handler_(handler)
    {
    }

  private:
    oem::Handler handler_;

    message::Response::ptr
        executeCallback(message::Request::ptr request) override
    {
        auto response = request->makeResponse();
        size_t len = request->raw.size();
        // (re-)allocate a big request buffer here
        request->raw.resize(64 * 1024);
        // allocate a big response buffer here
        response->raw.resize(64 * 1024);

        auto ccRet = handler_(request->ctx->cmd, request->raw.data(),
                              response->raw.data(), &len);
        response->cc = ccRet;
        response->raw.resize(len);
        return response;
    }
};

inline auto makeLegacyHandler(const ipmid_callback_t& handler)
{
    HandlerBase::ptr ptr(new IpmiHandler<ipmid_callback_t>(handler));
    return ptr;
}

inline auto makeLegacyHandler(oem::Handler&& handler)
{
    HandlerBase::ptr ptr(
        new IpmiHandler<oem::Handler>(std::forward<oem::Handler>(handler)));
    return ptr;
}
#endif // ALLOW_DEPRECATED_API

template <typename Handler>
inline auto makeHandler(Handler&& handler)
{
    HandlerBase::ptr ptr(
        new IpmiHandler<Handler>(std::forward<Handler>(handler)));
    return ptr;
}

} // namespace ipmi
