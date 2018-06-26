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

#include <tuple>
#include <ipmi/message/types.hpp>

namespace ipmi
{

namespace message
{

namespace details
{

/**************************************
 * ipmi return type helpers
 **************************************/

// types we need to handle:
// 1. uint8_t
// 2. uint16_t
// 3. uint32_t
// 4. random bitfields (bitset<N>)
// 5. pair of any of the above
// 6. tuple of any of the above
// 7. array of any of the above (known length)
// 8. vector of any of the above (unknown length)
// 9. ????


/** @struct unpack_single
 *  @brief Utility to unpack a single C++ element from a Request
 *
 *  User-defined types are expected to specialize this template in order to
 *  get their functionality.
 *
 *  @tparam S - Type of element to unpack.
 */
template <typename S> struct unpack_single
{
    // Downcast
    template <typename T> using Td = types::details::type_id_downcast_t<T>;

    /** @brief Do the operation to unpack element.
     *
     *  @tparam T - Type of element to unpack.
     *
     *  Template parameters T (function) and S (class) are different
     *  to allow the function to be utilized for many varients of S:
     *  S&, S&&, const S&, volatile S&, etc. The type_id_downcast is used
     *  to ensure T and S are equivalent.  For 'char*', this also allows
     *  use for 'char[N]' types.
     *
     *  @param[in] m - Request to unpack from.
     *  @param[out] t - The reference to unpack item into.
     */
    template <typename T,
              typename = std::enable_if_t<std::is_same<S, Td<T>>::value>>
    static int op(Request& m, T& t)
    {
        // For this default implementation, we need to ensure that only
        // basic types are used.
        static_assert(std::is_fundamental<Td<T>>::value,
                      "Non-basic types are not allowed.");

        // copy out bits from vector....
        /* for unpacking big-ending, you can use a reverse_iterator
        auto fiter = m.raw.begin() + m.rawIndex + sizeof(t);
        auto riter = std::make_reverse_iterator(fiter);
        */
        if (m.raw.size() < (m.rawIndex + sizeof(t)))
        {
          std::cerr << "unpack error: requesting too many bytes\n";
          return 1;
        }
        auto fiter = m.raw.begin() + m.rawIndex;
        std::copy_n(fiter, sizeof(t),
            reinterpret_cast<uint8_t*>(&t));
        // std::cerr << "consumed " << sizeof(t) <<" bytes\n";
        m.rawIndex += sizeof(t);
        return 0;
    }
};

// TODO VM: what to do with request as arg?
/*
template <>
struct unpack_single<Request>
{
  static int op(Request& m, Request& t)
  {
    t = m;
    return 0;
  }
};
*/

/** @struct unpack_single
 *  @brief Utility to unpack a single C++ element from a Request
 *
 *  Specialization to unpack std::string represented as a
 *  UCSD-Pascal style string
 */
template <>
struct unpack_single<std::string>
{
  static int op(Request& m, std::string& t)
  {
    // pop len first
    uint8_t len;
    m.unpack(len);
    // check to see that there are n bytes left
    char *first, *last;
    std::tie<char*, char*>(first, last) = m.pop<char>(len);
    // structured bindings syntax:
    // auto& [first, last] = m.pop<char>(len);
    if (first == last)
    {
      return 1;
    }
    t.insert(0, first, (last - first));
    return 0;
  }
};

/** @brief Specialization of pack_single for fixed_uint_t types
 */
template <unsigned N>
struct unpack_single<fixed_uint_t<N>>
{
  static int op(Request& m, fixed_uint_t<N>& t)
  {
    constexpr size_t count = N;
    // acquire enough bits in the stream to fulfill the request
    if (m.fillBits(count) < 0)
    {
      return -1;
    }
    uint64_t bitmask = uint64_t((1 << count) - 1) << (m.bitCount - count);
    t = (m.bitStream >> (m.bitCount - count));
    // clear bits from stream
    m.bitStream &= ~bitmask;
    m.bitCount -= count;
    return 0;
  }
};

/** @brief Specialization of unpack_single for bool. */
template <> struct unpack_single<bool>
{
  static int op(Request& m, bool& b)
  {
    // acquire enough bits in the stream to fulfill the request
    if (m.fillBits(1) < 0)
    {
      return -1;
    }
    uint64_t bitmask = uint64_t(1) << (m.bitCount - 1);
    b = static_cast<bool>(m.bitStream >> (m.bitCount - 1));
    // clear bits from stream
    m.bitStream &= ~bitmask;
    m.bitCount--;
    return 0;
  }
};

/** @brief Specialization of pack_single for std::bitset<N>
 */
template <size_t N>
struct unpack_single<std::bitset<N>>
{
  static int op(Request& m, std::bitset<N>& t)
  {
    constexpr size_t count = N;
    // acquire enough bits in the stream to fulfill the request
    if (m.fillBits(count) < 0)
    {
      return -1;
    }
    uint64_t bitmask = uint64_t((1 << count) - 1) << (m.bitCount - count);
    t = std::bitset<N>(m.bitStream >> (m.bitCount - count));
    // clear bits from stream
    m.bitStream &= ~bitmask;
    m.bitCount -= count;
    return 0;
  }
};

} // namespace details

} // namespace message

} // namespace ipmi
