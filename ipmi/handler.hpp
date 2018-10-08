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
#include <user_channel/channel_layer.hpp>
#include <utility>

#ifdef ALLOW_DEPRECATED_API
#include <ipmid/api.h>

#include <ipmid/oemrouter.hpp>
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
        return executeCallback(request);
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
class IpmiHandler final : public HandlerBase
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
        message::Response::ptr response = request->makeResponse();

        using CallbackSig = boost::callable_traits::args_t<Handler>;
        using InputArgsType = typename utility::DecayTuple<CallbackSig>::type;
        using UnpackArgsType = typename utility::StripFirstArgs<
            utility::NonIpmiArgsCount<InputArgsType>::size(),
            InputArgsType>::type;
        using ResultType = boost::callable_traits::return_type_t<Handler>;

        UnpackArgsType unpackArgs;
        ipmi::Cc unpackError = request->unpack(unpackArgs);
        if (unpackError != ipmi::ccSuccess)
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
        ResultType result;
        try
        {
            // execute the registered callback function and get the
            // ipmi::RspType<>
            result = std::apply(handler_, *inputArgs);
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Handler failed to catch exception",
                phosphor::logging::entry("EXCEPTION=%s", e.what()),
                phosphor::logging::entry("NETFN=%x", request->ctx->netFn),
                phosphor::logging::entry("CMD=%x", request->ctx->cmd));
            return errorResponse(request, ccUnspecifiedError);
        }

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
class IpmiHandler<ipmid_callback_t> final : public HandlerBase
{
  public:
    explicit IpmiHandler(const ipmid_callback_t& handler) : handler_(handler)
    {
    }

  private:
    ipmid_callback_t handler_;

    /* specialization for legacy handler */
    message::Response::ptr
        executeCallback(message::Request::ptr request) override
    {
        message::Response::ptr response = request->makeResponse();
        size_t len = request->payload.size();
        // allocate a big response buffer here
        response->payload.resize(
            getChannelMaxTransferSize(request->ctx->channel));

        Cc ccRet{ccSuccess};
        try
        {
            ccRet = handler_(request->ctx->netFn, request->ctx->cmd,
                             request->payload.data(), response->payload.data(),
                             &len, nullptr);
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Legacy Handler failed to catch exception",
                phosphor::logging::entry("EXCEPTION=%s", e.what()),
                phosphor::logging::entry("NETFN=%x", request->ctx->netFn),
                phosphor::logging::entry("CMD=%x", request->ctx->cmd));
            return errorResponse(request, ccUnspecifiedError);
        }
        response->cc = ccRet;
        response->payload.resize(len);
        return response;
    }
};
template <>
class IpmiHandler<oem::Handler> final : public HandlerBase
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
        message::Response::ptr response = request->makeResponse();
        size_t len = request->payload.size();
        // allocate a big response buffer here
        response->payload.resize(
            getChannelMaxTransferSize(request->ctx->channel));

        Cc ccRet{ccSuccess};
        try
        {
            ccRet = handler_(request->ctx->cmd, request->payload.data(),
                             response->payload.data(), &len);
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Legacy OEM Handler failed to catch exception",
                phosphor::logging::entry("EXCEPTION=%s", e.what()),
                phosphor::logging::entry("NETFN=%x", request->ctx->netFn),
                phosphor::logging::entry("CMD=%x", request->ctx->cmd));
            return errorResponse(request, ccUnspecifiedError);
        }
        response->cc = ccRet;
        response->payload.resize(len);
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
