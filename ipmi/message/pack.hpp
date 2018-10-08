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
#include <memory>
#include <phosphor-logging/log.hpp>
#include <tuple>
#include <utility>
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

template <typename NumericType, size_t byteIndex = 0>
void PackBytes(uint8_t* pointer, const NumericType& i)
{
    if constexpr (byteIndex < sizeof(NumericType))
    {
        *pointer = static_cast<uint8_t>(i >> (8 * byteIndex));
        PackBytes<NumericType, byteIndex + 1>(pointer + 1, i);
    }
}

template <typename NumericType, size_t byteIndex = 0>
void PackBytesUnaligned(Payload& p, const NumericType& i)
{
    if constexpr (byteIndex < sizeof(NumericType))
    {
        p.appendBits(CHAR_BIT, static_cast<uint8_t>(i >> (8 * byteIndex)));
        PackBytesUnaligned<NumericType, byteIndex + 1>(p, i);
    }
}

/** @struct PackSingle
 *  @brief Utility to pack a single C++ element into a Payload
 *
 *  User-defined types are expected to specialize this template in order to
 *  get their functionality.
 *
 *  @tparam S - Type of element to pack.
 */
template <typename T>
struct PackSingle
{
    /** @brief Do the operation to pack element.
     *
     *  @param[in] p - Payload to pack into.
     *  @param[out] t - The reference to pack item into.
     */
    static int op(Payload& p, T& t)
    {
        // if not on a byte boundary, must pack values LSbit/LSByte first
        if (p.bitCount)
        {
            PackBytesUnaligned<T>(p, t);
        }
        else
        {
            // copy in bits to vector....
            p.raw.resize(p.raw.size() + sizeof(T));
            uint8_t* out = p.raw.data() + p.raw.size() - sizeof(T);
            PackBytes<T>(out, t);
        }
        return 0;
    }
};

/** @brief Specialization of PackSingle for std::string
 *  represented as a UCSD-Pascal style string
 */
template <>
struct PackSingle<std::string>
{
    static int op(Payload& p, std::string& t)
    {
        // check length first
        uint8_t len;
        if (t.length() > std::numeric_limits<decltype(len)>::max())
        {
            using namespace phosphor::logging;
            log<level::ERR>("long string truncated on IPMI message pack");
            return 1;
        }
        len = static_cast<uint8_t>(t.length());
        PackSingle<uint8_t>::op(p, len);
        p.append(t.c_str(), t.c_str() + t.length());
        return 0;
    }
};

/** @brief Specialization of PackSingle for fixed_uint_t types
 */
template <unsigned N>
struct PackSingle<fixed_uint_t<N>>
{
    static int op(Payload& p, fixed_uint_t<N>& t)
    {
        size_t count = N;
        static_assert(N <= (details::bitStreamSize - CHAR_BIT));
        uint64_t bits = t;
        while (count > 0)
        {
            size_t appendCount = std::min(count, static_cast<size_t>(CHAR_BIT));
            p.appendBits(appendCount, static_cast<uint8_t>(bits));
            bits >>= CHAR_BIT;
            count -= appendCount;
        }
        return 0;
    }
};

/** @brief Specialization of PackSingle for bool. */
template <>
struct PackSingle<bool>
{
    static int op(Payload& p, bool& b)
    {
        p.appendBits(1, b);
        return 0;
    }
};

/** @brief Specialization of PackSingle for std::bitset<N> */
template <size_t N>
struct PackSingle<std::bitset<N>>
{
    static int op(Payload& p, std::bitset<N>& t)
    {
        size_t count = N;
        static_assert(N <= (details::bitStreamSize - CHAR_BIT));
        unsigned long long bits = t.to_ullong();
        while (count > 0)
        {
            size_t appendCount = std::min(count, size_t(CHAR_BIT));
            p.appendBits(appendCount, static_cast<uint8_t>(bits));
            bits >>= CHAR_BIT;
            count -= appendCount;
        }
        return 0;
    }
};

/** @brief Specialization of PackSingle for std::array<T, N> */
template <typename T, size_t N>
struct PackSingle<std::array<T, N>>
{
    static int op(Payload& p, std::array<T, N>& t)
    {
        int ret = 0;
        for (auto v : t)
        {
            int ret = PackSingle<T>::op(p, v);
            if (ret)
            {
                break;
            }
        }
        return ret;
    }
};

/** @brief Specialization of PackSingle for std::vector<T, N> */
template <typename T>
struct PackSingle<std::vector<T>>
{
    static int op(Payload& p, std::vector<T>& t)
    {
        int ret = 0;
        for (auto v : t)
        {
            int ret = PackSingle<T>::op(p, v);
            if (ret)
            {
                break;
            }
        }
        return ret;
    }
};

/** @brief Specialization of PackSingle for std::vector<uint8_t> */
template <>
struct PackSingle<std::vector<uint8_t>>
{
    static int op(Payload& p, std::vector<uint8_t>& t)
    {
        p.raw.reserve(p.raw.size() + t.size());
        p.raw.insert(p.raw.end(), t.begin(), t.end());
        return 0;
    }
};

} // namespace details

} // namespace message

} // namespace ipmi
