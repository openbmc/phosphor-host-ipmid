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
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
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

    /** @brief wrap the call to the registered handler with the request
     *
     * This is called from the running queue context after it has already
     * created a request object that contains all the information required to
     * execute the ipmi command. This function will return the response object
     * pointer that owns the response object that will ultimately get sent back
     * to the requester.
     *
     * This is a non-virtual function wrapper to the virtualized executeCallback
     * function that actually does the work. This is required because of how
     * templates and virtualization work together.
     *
     * @param request a shared_ptr to a Request object
     *
     * @return a shared_ptr to a Response object
     */
    message::Response::ptr call(message::Request::ptr request)
    {
        return executeCallback(request);
    }

  private:
    /** @brief call the registered handler with the request
     *
     * This is called from the running queue context after it has already
     * created a request object that contains all the information required to
     * execute the ipmi command. This function will return the response object
     * pointer that owns the response object that will ultimately get sent back
     * to the requester.
     *
     * @param request a shared_ptr to a Request object
     *
     * @return a shared_ptr to a Response object
     */
    virtual message::Response::ptr
        executeCallback(message::Request::ptr request) = 0;
};

/**
 * @brief Main IPMI handler class
 *
 * New IPMI handlers will resolve into this class, which will read the signature
 * of the registering function, attempt to extract the appropriate arguments
 * from a request, pass the arguments to the function, and then pack the
 * response of the function back into an IPMI response.
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

    /** @brief call the registered handler with the request
     *
     * This is called from the running queue context after it has already
     * created a request object that contains all the information required to
     * execute the ipmi command. This function will return the response object
     * pointer that owns the response object that will ultimately get sent back
     * to the requester.
     *
     * Because this is the new variety of IPMI handler, this is the function
     * that attempts to extract the requested parameters in order to pass them
     * onto the callback function and then packages up the response into a plain
     * old vector to pass back to the caller.
     *
     * @param request a shared_ptr to a Request object
     *
     * @return a shared_ptr to a Response object
     */
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
        /* callbacks can contain an optional first arument of one of:
         * 1) boost::asio::yield_context
         * 2) ipmi::Context::ptr
         * 3) ipmi::message::Request::ptr
         *
         * If any of those is part of the callback signature as the first
         * argument, it will automatically get packed into the parameter pack
         * here.
         */
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
                // no special parameters were requested (but others were)
                inputArgs.emplace(std::move(unpackArgs));
            }
        }
        else
        {
            // no parameters were requested
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
        catch (...)
        {
            std::exception_ptr eptr;
            try
            {
                eptr = std::current_exception();
                if (eptr)
                {
                    std::rethrow_exception(eptr);
                }
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
/**
 * @brief Legacy IPMI handler class
 *
 * Legacy IPMI handlers will resolve into this class, which will behave the same
 * way as the legacy IPMI queue, passing in a big buffer for the request and a
 * big buffer for the response.
 *
 * As soon as all the handlers have been rewritten, this class will be marked as
 * deprecated and eventually removed.
 */
template <>
class IpmiHandler<ipmid_callback_t> final : public HandlerBase
{
  public:
    explicit IpmiHandler(const ipmid_callback_t& handler) : handler_(handler)
    {
    }

  private:
    ipmid_callback_t handler_;

    /** @brief call the registered handler with the request
     *
     * This is called from the running queue context after it has already
     * created a request object that contains all the information required to
     * execute the ipmi command. This function will return the response object
     * pointer that owns the response object that will ultimately get sent back
     * to the requester.
     *
     * Because this is the legacy variety of IPMI handler, this function does
     * not really have to do much other than pass the payload to the callback
     * and return response to the caller.
     *
     * @param request a shared_ptr to a Request object
     *
     * @return a shared_ptr to a Response object
     */
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
        catch (...)
        {
            std::exception_ptr eptr;
            try
            {
                eptr = std::current_exception();
                if (eptr)
                {
                    std::rethrow_exception(eptr);
                }
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
        }
        response->cc = ccRet;
        response->payload.resize(len);
        return response;
    }
};

/**
 * @brief create a legacy IPMI handler class and return a shared_ptr
 *
 * The queue uses a map of pointers to do the lookup. This function returns the
 * shared_ptr that owns the Handler object.
 *
 * This is called internally via the ipmi_register_callback function.
 *
 * @param handler the function pointer to the callback
 *
 * @return A shared_ptr to the created handler object
 */
inline auto makeLegacyHandler(const ipmid_callback_t& handler)
{
    HandlerBase::ptr ptr(new IpmiHandler<ipmid_callback_t>(handler));
    return ptr;
}

#endif // ALLOW_DEPRECATED_API

/**
 * @brief create an IPMI handler class and return a shared_ptr
 *
 * The queue uses a map of pointers to do the lookup. This function returns the
 * shared_ptr that owns the Handler object.
 *
 * This is called internally via the ipmi::registerHandler function.
 *
 * @param handler the function pointer to the callback
 *
 * @return A shared_ptr to the created handler object
 */
template <typename Handler>
inline auto makeHandler(Handler&& handler)
{
    HandlerBase::ptr ptr(
        new IpmiHandler<Handler>(std::forward<Handler>(handler)));
    return ptr;
}

} // namespace ipmi
