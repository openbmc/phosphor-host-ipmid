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

#include <array>
#include <ipmi/message/types.hpp>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace ipmi
{

namespace message
{

namespace details
{

/**************************************
 * ipmi return type helpers
 **************************************/

template <size_t byteIndex, typename NumericType>
void UnpackByte(uint8_t* pointer, NumericType& i)
{
    if constexpr (byteIndex > 0)
    {
        i += *pointer << (8 * (byteIndex - 1));
        UnpackByte<byteIndex - 1, NumericType>(pointer + 1, i);
    }
}

/** @struct UnpackSingle
 *  @brief Utility to unpack a single C++ element from a Payload
 *
 *  User-defined types are expected to specialize this template in order to
 *  get their functionality.
 *
 *  @tparam T - Type of element to unpack.
 */
template <typename T>
struct UnpackSingle
{
    /** @brief Do the operation to unpack element.
     *
     *  @param[in] p - Payload to unpack from.
     *  @param[out] t - The reference to unpack item into.
     */
    //    template <typename S,
    //              typename = std::enable_if_t<std::is_fundamental<S>::value>>
    static int op(Payload& p, T& t)
    {
        // copy out bits from vector....
        if (p.raw.size() < (p.rawIndex + sizeof(t)))
        {
            return 1;
        }
        auto iter = p.raw.data() + p.rawIndex;
        t = 0;
        UnpackByte<sizeof(T), T>(iter, t);
        p.rawIndex += sizeof(t);
        return 0;
    }
};

/** @struct UnpackSingle
 *  @brief Utility to unpack a single C++ element from a Payload
 *
 *  Specialization to unpack std::string represented as a
 *  UCSD-Pascal style string
 */
template <>
struct UnpackSingle<std::string>
{
    static int op(Payload& p, std::string& t)
    {
        // pop len first
        if (p.rawIndex > (p.raw.size() - sizeof(uint8_t)))
        {
            return 1;
        }
        uint8_t len = p.raw[p.rawIndex++];
        // check to see that there are n bytes left
        auto [first, last] = p.pop<char>(len);
        if (first == last)
        {
            return 1;
        }
        t.reserve(last - first);
        t.insert(0, first, (last - first));
        return 0;
    }
};

/** @brief Specialization of UnpackSingle for fixed_uint_t types
 */
template <unsigned N>
struct UnpackSingle<fixed_uint_t<N>>
{
    static int op(Payload& p, fixed_uint_t<N>& t)
    {
        static_assert(N <= (sizeof(details::bitStreamSize) - CHAR_BIT));
        constexpr size_t count = N;
        // acquire enough bits in the stream to fulfill the Payload
        if (p.fillBits(count) < 0)
        {
            return -1;
        }
        fixed_uint_t<details::bitStreamSize> bitmask(1);
        bitmask <<= count;
        bitmask -= 1;
        bitmask <<= (p.bitCount - count);
        t = (p.bitStream >> (p.bitCount - count));
        // clear bits from stream
        p.bitStream &= ~bitmask;
        p.bitCount -= count;
        return 0;
    }
};

/** @brief Specialization of UnpackSingle for bool. */
template <>
struct UnpackSingle<bool>
{
    static int op(Payload& p, bool& b)
    {
        // acquire enough bits in the stream to fulfill the Payload
        if (p.fillBits(1) < 0)
        {
            return -1;
        }
        fixed_uint_t<details::bitStreamSize> bitmask(1);
        bitmask <<= (p.bitCount - 1);
        b = static_cast<bool>(p.bitStream >> (p.bitCount - 1));
        // clear bits from stream
        p.bitStream &= ~bitmask;
        p.bitCount--;
        return 0;
    }
};

/** @brief Specialization of UnpackSingle for std::bitset<N>
 */
template <size_t N>
struct UnpackSingle<std::bitset<N>>
{
    static int op(Payload& p, std::bitset<N>& t)
    {
        static_assert(N <= (sizeof(details::bitStreamSize) - CHAR_BIT));
        constexpr size_t count = N;
        // acquire enough bits in the stream to fulfill the Payload
        if (p.fillBits(count) < 0)
        {
            return -1;
        }
        fixed_uint_t<details::bitStreamSize> bitmask(1);
        bitmask <<= count;
        bitmask -= 1;
        bitmask <<= (p.bitCount - count);
        t = std::bitset<N>(p.bitStream >> (p.bitCount - count));
        // clear bits from stream
        p.bitStream &= ~bitmask;
        p.bitCount -= count;
        return 0;
    }
};

/** @brief Specialization of UnpackSingle for std::optional<T> */
template <typename T>
struct UnpackSingle<std::optional<T>>
{
    static int op(Payload& p, std::optional<T>& t)
    {
        t.emplace();
        int ret = UnpackSingle<T>::op(p, *t);
        if (ret != 0)
        {
            t.reset();
        }
        return 0;
    }
};

/** @brief Specialization of UnpackSingle for std::array<T, N> */
template <typename T, size_t N>
struct UnpackSingle<std::array<T, N>>
{
    static int op(Payload& p, std::array<T, N>& t)
    {
        int ret = 0;
        for (auto& v : t)
        {
            ret = UnpackSingle<T>::op(p, v);
            if (ret)
            {
                break;
            }
        }
        return ret;
    }
};

/** @brief Specialization of UnpackSingle for std::vector<T> */
template <typename T>
struct UnpackSingle<std::vector<T>>
{
    static int op(Payload& p, std::vector<T>& t)
    {
        int ret = 0;
        while (p.rawIndex < p.raw.size())
        {
            t.emplace_back();
            ret = UnpackSingle<T>::op(p, t.back());
            if (ret)
            {
                t.pop_back();
                break;
            }
        }
        return ret;
    }
};

/** @brief Specialization of UnpackSingle for std::vector<uint8_t> */
template <>
struct UnpackSingle<std::vector<uint8_t>>
{
    static int op(Payload& p, std::vector<uint8_t>& t)
    {
        // copy out the remainder of the message
        t.reserve(p.raw.size() - p.rawIndex);
        t.insert(t.begin(), p.raw.begin() + p.rawIndex, p.raw.end());
        p.rawIndex = p.raw.size();
        return 0;
    }
};

/** @brief Specialization of UnpackSingle for std::vector<uint8_t> */
template <>
struct UnpackSingle<Payload>
{
    static int op(Payload& p, Payload& t)
    {
        // mark that this payload is being included in the args
        p.trailingOk = true;
        t = p;
        return 0;
    }
};

} // namespace details

} // namespace message

} // namespace ipmi
