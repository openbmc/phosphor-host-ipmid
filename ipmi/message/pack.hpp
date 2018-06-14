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

#if __has_include(<experimental/tuple>)
#include <experimental/tuple>
namespace std
{
  using experimental::apply;
}
#else
#include <tuple>
#endif
#include <memory>
#include <utility>
#include <vector>
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


/** @struct pack_single
 *  @brief Utility to pack a single C++ element into a Response
 *
 *  User-defined types are expected to specialize this template in order to
 *  get their functionality.
 *
 *  @tparam S - Type of element to pack.
 */
template <typename S> struct pack_single
{
    // Downcast
    template <typename T> using Td = types::details::type_id_downcast_t<T>;

    /** @brief Do the operation to pack element.
     *
     *  @tparam T - Type of element to pack.
     *
     *  Template parameters T (function) and S (class) are different
     *  to allow the function to be utilized for many varients of S:
     *  S&, S&&, const S&, volatile S&, etc. The type_id_downcast is used
     *  to ensure T and S are equivalent.  For 'char*', this also allows
     *  use for 'char[N]' types.
     *
     *  @param[in] m - Response to pack into.
     *  @param[out] t - The reference to pack item into.
     */
    template <typename T,
              typename = std::enable_if_t<std::is_same<S, Td<T>>::value>>
    static int op(Response& m, T& t)
    {
        // For this default implementation, we need to ensure that only
        // basic types are used.
        static_assert(std::is_fundamental<Td<T>>::value,
                      "Non-basic types are not allowed.");

        // copy in bits to vector....
        auto fiter = reinterpret_cast<uint8_t*>(&t);
        auto eiter = fiter + sizeof(t);
        m.raw.insert(m.raw.end(), fiter, eiter);
        // std::cerr << "consumed " << sizeof(t)*8 <<" bits\n";
        m.bits += (8 * sizeof(t));
        return 0;
    }
};

/** @brief Specialization of pack_single for std::string
 *  represented as a UCSD-Pascal style string
 */
template <>
struct pack_single<std::string>
{
  static int op(Response& m, std::string& t)
  {
    // check length first
    uint8_t len;
    if (t.length() > std::numeric_limits<decltype(len)>::max())
    {
      // TODO VM: throw, log, what? Some error reporting.
      return 1;
    }
    len = static_cast<uint8_t>(t.length());
    m.pack(len);
    m.append(t.c_str(), t.c_str() + t.length());
    return 0;
  }
};

#if 0
/** @brief Specialization of pack_single for std::bitset<N> */
template <size_t N>
struct pack_single<std::bitset<N>>
{
  static int op(Response& m, std::bitset<N>& t)
  {
    // check if we need to shift
    return 0;
  }
};

/** @brief Specialization of pack_single for bool. */
template <> struct pack_single<bool>
{
    static int op(sd_bus_message* m, bool& b)
    {
        m.pack_bit(b);
        return 0;
    }
};
#endif /* 0 */

} // namespace details

} // namespace message

} // namespace ipmi
