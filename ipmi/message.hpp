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
#include <phosphor-logging/log.hpp>
#include <tuple>
#include <utility>
#include <vector>

namespace ipmi
{

struct Context
{
    using ptr = std::shared_ptr<Context>;

    Context() :
        netFn(0), cmd(0), channel(0), userId(0), priv(Privilege::None),
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

// size to hold 64 bits plus one (possibly-)partial byte
static constexpr size_t bitStreamSize = ((sizeof(uint64_t) + 1) * CHAR_BIT);

} // namespace details

struct Payload
{
    Payload() = default;
    Payload(const Payload&) = default;
    Payload& operator=(const Payload&) = default;
    Payload(Payload&&) = default;
    Payload& operator=(Payload&&) = default;

    explicit Payload(std::vector<uint8_t>& data) : raw(data), unpackCheck(false)
    {
    }

    ~Payload()
    {
        using namespace phosphor::logging;
        if (trailingOk && !unpackCheck && !fullyUnpacked())
        {
            log<level::ERR>("Failed to check request for full unpack");
        }
    }

    /******************************************************************
     * raw vector access
     *****************************************************************/
    size_t size() const
    {
        return raw.size();
    }
    void resize(size_t sz)
    {
        raw.resize(sz);
    }
    uint8_t* data()
    {
        return raw.data();
    }
    const uint8_t* data() const
    {
        return raw.data();
    }

    /******************************************************************
     * Response operations
     *****************************************************************/
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

        // add in the new bits as the higher-order bits, filling LSBit first
        fixed_uint_t<details::bitStreamSize> tmp = bits;
        tmp <<= bitCount;
        bitStream |= tmp;
        bitCount += count;

        // drain any whole bytes we have appended
        drain(true);
    }

    /* empty out the bucket and pack it as bytes LSB-first */
    void drain(bool wholeBytesOnly = false)
    {
        while (bitCount > 0)
        {
            uint8_t retVal;
            if (bitCount < CHAR_BIT)
            {
                if (wholeBytesOnly)
                {
                    break;
                }
            }
            size_t bitsOut = std::min(static_cast<size_t>(CHAR_BIT), bitCount);
            retVal = static_cast<uint8_t>(bitStream);
            raw.push_back(retVal);
            bitStream >>= bitsOut;
            bitCount -= bitsOut;
        }
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

    /******************************************************************
     * Request operations
     *****************************************************************/

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
        unpackError = true;
        return std::make_tuple(reinterpret_cast<T*>(NULL),
                               reinterpret_cast<T*>(NULL));
    }

    /** @brief fill bit stream with at least count bits for consumption
     *
     * @param[in] count - number of bit needed
     * @return - unpackError
     */
    bool fillBits(size_t count)
    {
        // add more bits to the top end of the bitstream
        // so we consume bits least-significant first
        if (count > (details::bitStreamSize - CHAR_BIT))
        {
            unpackError = true;
            return unpackError;
        }
        while (bitCount < count)
        {
            if (rawIndex < raw.size())
            {
                fixed_uint_t<details::bitStreamSize> tmp = raw[rawIndex++];
                tmp <<= bitCount;
                bitStream |= tmp;
                bitCount += CHAR_BIT;
            }
            else
            {
                // raw has run out of bytes to pop
                unpackError = true;
                return unpackError;
            }
        }
        return false;
    }

    /** @brief consume count bits from bitstream (must call fillBits first)
     *
     * @param[in] count - number of bit needed
     * @return - count bits from stream
     */
    uint8_t popBits(size_t count)
    {
        if (bitCount < count)
        {
            unpackError = true;
            return 0;
        }
        // consume bits low-order bits first
        auto bits = bitStream.convert_to<uint8_t>();
        bits &= ((1 << count) - 1);
        bitStream >>= count;
        bitCount -= count;
        return bits;
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
        unpackError = false;
    }

    bool fullyUnpacked()
    {
        unpackCheck = true;
        return raw.size() == rawIndex && bitCount == 0 && !unpackError;
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
            unpackError = true;
            return unpackRet;
        }
        return unpack(std::forward<Args>(args)...);
    }

    template <typename... Types>
    int unpack(std::tuple<Types...>& t)
    {
        // roll back checkpoint so that unpacking a tuple is atomic
        size_t priorBitCount = bitCount;
        size_t priorIndex = rawIndex;
        fixed_uint_t<details::bitStreamSize> priorBits = bitStream;

        int ret =
            std::apply([this](Types&... args) { return unpack(args...); }, t);
        if (ret)
        {
            bitCount = priorBitCount;
            bitStream = priorBits;
            rawIndex = priorIndex;
        }

        return ret;
    }

    // partial bytes in the form of bits
    fixed_uint_t<details::bitStreamSize> bitStream;
    size_t bitCount = 0;
    std::vector<uint8_t> raw;
    size_t rawIndex = 0;
    bool trailingOk = false;
    bool unpackCheck = true;
    bool unpackError = false;
};

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
        payload(), ctx(context), cc(ccSuccess)
    {
    }

    template <typename... Args>
    int pack(Args&&... args)
    {
        return payload.pack(std::forward<Args>(args)...);
    }

    template <typename... Types>
    int pack(std::tuple<Types...>& t)
    {
        return payload.pack(t);
    }

    Payload payload;
    Context::ptr ctx;
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
        payload(d), ctx(context)
    {
    }

    template <typename... Args>
    int unpack(Args&&... args)
    {
        int unpackRet = payload.unpack(std::forward<Args>(args)...);
        if (unpackRet == ipmi::ccSuccess)
        {
            if (!payload.trailingOk)
            {
                if (!payload.fullyUnpacked())
                {
                    // not all bits were consumed by requested parameters
                    return ipmi::ccReqDataLenInvalid;
                }
                payload.unpackCheck = false;
            }
        }
        return unpackRet;
    }

    template <typename... Types>
    int unpack(std::tuple<Types...>& t)
    {
        return std::apply([this](Types&... args) { return unpack(args...); },
                          t);
    }

    /** @brief Create a response message that corresponds to this request
     *
     * @return A shared_ptr to the response message created
     */
    Response::ptr makeResponse()
    {
        return std::make_shared<Response>(ctx);
    }

    Payload payload;
    Context::ptr ctx;
};

} // namespace message

} // namespace ipmi

// include packing and unpacking of types
#include <ipmi/message/pack.hpp>
#include <ipmi/message/unpack.hpp>
