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
#include <cstdint>
#include <ipmi/message/types.hpp>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

namespace ipmi
{

struct Context
{
    using ptr = std::shared_ptr<Context>;

    Context() :
        netFn(0), cmd(0), channel(0), userId(0), priv(privilegeNone),
        yield(nullptr)
    {
    }

    Context(NetFn netFn, Cmd cmd, int channel, int userId, Privilege priv,
            boost::asio::yield_context* yield = nullptr) :
        netFn(netFn),
        cmd(cmd), channel(channel), userId(userId), priv(priv), yield(yield)
    {
    }

    // normal IPMI context (what call is this, from whence it came...)
    NetFn netFn;
    Cmd cmd;
    int channel;
    int userId;
    Privilege priv;
    // if non-null, use this to do blocking asynchronous asio calls
    boost::asio::yield_context* yield;
    // TODO VM: what about user context -- legacy's void*?
};

// forward declare message class
namespace message
{

namespace details
{

template <typename A>
struct UnpackSingle;

template <typename T>
using UnpackSingle_t = UnpackSingle<utility::TypeIdDowncast_t<T>>;

template <typename A>
struct PackSingle;

template <typename T>
using PackSingle_t = PackSingle<utility::TypeIdDowncast_t<T>>;

} // namespace details

struct Response
{
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor to avoid nullptrs.
     *     Allowed:
     *         - Copy operations.
     *         - Move operations.
     *         - Destructor.
     */
    Response() = delete;
    Response(const Response&) = default;
    Response& operator=(const Response&) = default;
    Response(Response&&) = default;
    Response& operator=(Response&&) = default;
    ~Response() = default;

    using ptr = std::shared_ptr<Response>;

    explicit Response(Context::ptr& context) :
        bitStream(0), bitCount(0), ctx(context), cc(ccSuccess)
    {
    }

    // base empty pack
    int pack()
    {
        return 0;
    }

    template <typename Arg, typename... Args>
    int pack(Arg&& arg, Args&&... args)
    {
        int packRet =
            details::PackSingle_t<Arg>::op(*this, std::forward<Arg>(arg));
        if (packRet)
        {
            return packRet;
        }
        packRet = pack(std::forward<Args>(args)...);
        drain();
        return packRet;
    }

    template <typename... Types>
    int pack(std::tuple<Types...>& t)
    {
        return std::apply([this](Types&... args) { return pack(args...); }, t);
    }

    template <typename T>
    void append(T* begin, T* end)
    {
        // this interface only allows full-byte access; pack in partial bytes
        drain();
        raw.insert(raw.end(), reinterpret_cast<const uint8_t*>(begin),
                   reinterpret_cast<const uint8_t*>(end));
    }

    void appendBits(size_t count, uint8_t bits)
    {
        // drain whole bytes out
        drain(true);

        // add in the new bits
        bitStream <<= count;
        bitStream |= bits;
        bitCount += count;

        // drain any whole bytes we have appended
        drain(true);
    }

    /* empty out the bucket and pack it as bytes LSB-first */
    void drain(bool wholeBytesOnly = false)
    {
        while (bitCount > 0)
        {
            if (wholeBytesOnly && bitCount < CHAR_BIT)
            {
                break;
            }
            uint8_t retVal = static_cast<uint8_t>(bitStream);
            bitStream >>= CHAR_BIT;
            bitCount -= std::min(size_t(CHAR_BIT), bitCount);
            pack(retVal);
        }
    }

    // partial bytes in the form of bits
    uint64_t bitStream;
    size_t bitCount;
    Context::ptr ctx;
    std::vector<uint8_t> raw;
    Cc cc;
};

struct Request
{
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor to avoid nullptrs.
     *     Allowed:
     *         - Copy operations.
     *         - Move operations.
     *         - Destructor.
     */
    Request() = delete;
    Request(const Request&) = default;
    Request& operator=(const Request&) = default;
    Request(Request&&) = default;
    Request& operator=(Request&&) = default;
    ~Request() = default;

    using ptr = std::shared_ptr<Request>;

    explicit Request(Context::ptr context, std::vector<uint8_t>& d) :
        ctx(context), raw(d), rawIndex(0), bitStream(0), bitCount(0)
    {
    }

    // base empty unpack
    int unpack()
    {
        return 0;
    }

    template <typename Arg, typename... Args>
    int unpack(Arg&& arg, Args&&... args)
    {
        int unpackRet =
            details::UnpackSingle_t<Arg>::op(*this, std::forward<Arg>(arg));
        if (unpackRet)
        {
            return unpackRet;
        }
        return unpack(std::forward<Args>(args)...);
    }

    template <typename... Types>
    int unpack(std::tuple<Types...>& t)
    {
        int unpack_ok =
            std::apply([this](Types&... args) { return unpack(args...); }, t);
        if (ipmi::ccSuccess == unpack_ok)
        {
            if (raw.size() == rawIndex && bitCount == 0)
            {
                // all bits were consumed by requested parameters
                return ipmi::ccSuccess;
            }
            return ipmi::ccReqDataLenInvalid;
        }
        return unpack_ok;
    }

    template <typename T>
    auto pop(size_t count)
    {
        // this interface only allows full-byte access; skip partial bits
        if (bitCount)
        {
            // WARN on unused bits?
            discardBits();
        }
        if (count <= (raw.size() - rawIndex))
        {
            auto range = std::make_tuple(
                reinterpret_cast<T*>(raw.data() + rawIndex),
                reinterpret_cast<T*>(raw.data() + rawIndex + count));
            rawIndex += count;
            return range;
        }
        return std::make_tuple(reinterpret_cast<T*>(NULL),
                               reinterpret_cast<T*>(NULL));
    }

    /** @brief Create a response message that corresponds to this request
     *
     * @return A shared_ptr to the response message created
     */
    Response::ptr makeResponse()
    {
        return std::make_shared<Response>(ctx);
    }

    /** @brief fill bit stream with at least count bits for consumption
     *
     * @param[in] count - number of bit needed
     * @return - 0 on success
     */
    int fillBits(size_t count)
    {
        // TODO: this could lose up to 7 bits...
        // think of the time where they request 64 bits but we only have 63 in
        // the stream. We pop one more byte to fill the stream and lose 7 bits.
        // 64 is a nice large number of bits, but if we limit the max
        // requestable bits to be 56, then we avoid this 7 bit loss nonsense.
        if (count > (sizeof(bitStream) - 1) * CHAR_BIT)
            return -1;
        while (bitCount < count)
        {
            if (rawIndex < raw.size())
            {
                bitStream <<= CHAR_BIT;
                bitStream |= raw[rawIndex++];
                bitCount += CHAR_BIT;
            }
            else
            {
                // raw has run out of bytes to pop
                return -1;
            }
        }
        return 0;
    }

    void discardBits()
    {
        bitStream = 0;
        bitCount = 0;
    }

    void reset()
    {
        discardBits();
        rawIndex = 0;
    }

    Context::ptr ctx;
    std::vector<uint8_t> raw;
    size_t rawIndex;
    uint64_t bitStream;
    size_t bitCount;
};

} // namespace message

} // namespace ipmi

// include packing and unpacking of types
#include <ipmi/message/pack.hpp>
#include <ipmi/message/unpack.hpp>
