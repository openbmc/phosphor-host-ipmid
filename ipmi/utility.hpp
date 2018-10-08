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
#include <boost/asio/spawn.hpp>
#include <boost/callable_traits.hpp>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

namespace ipmi
{

struct Context;

namespace utility
{

template <std::size_t N, typename FirstArg, typename... Rest>
struct StripFirstArgs;

template <std::size_t N, typename FirstArg, typename... Rest>
struct StripFirstArgs<N, std::tuple<FirstArg, Rest...>>
    : StripFirstArgs<N - 1, std::tuple<Rest...>>
{
};

template <typename FirstArg, typename... Rest>
struct StripFirstArgs<0, std::tuple<FirstArg, Rest...>>
{
    using type = std::tuple<FirstArg, Rest...>;
};
template <std::size_t N>
struct StripFirstArgs<N, std::tuple<>>
{
    using type = std::tuple<>;
};

// Small helper class for stripping off the error code from the function
// argument definitions so unpack can be called appropriately
template <typename T>
using StripFirstArg = StripFirstArgs<1, T>;

template <typename FirstArg, typename... Rest>
struct NonIpmiArgsCount;

template <>
struct NonIpmiArgsCount<std::tuple<>>
{
    constexpr static std::size_t size()
    {
        return 0;
    }
};
template <typename FirstArg, typename... OtherArgs>
struct NonIpmiArgsCount<std::tuple<FirstArg, OtherArgs...>>
{
    constexpr static std::size_t size()
    {
        if constexpr (std::is_same<FirstArg, ipmi::Context>::value ||
                      std::is_same<FirstArg, boost::asio::yield_context>::value)
        {
            return 1 + NonIpmiArgsCount<std::tuple<OtherArgs...>>::size();
        }
        else
        {
            return NonIpmiArgsCount<std::tuple<OtherArgs...>>::size();
        }
    }
};

// matching helper class to only return the first type
template <typename T>
struct GetFirstArg
{
    using type = void;
};

template <typename FirstArg, typename... Rest>
struct GetFirstArg<std::tuple<FirstArg, Rest...>>
{
    using type = FirstArg;
};

// helper class to remove const and reference from types
template <typename... Args>
struct DecayTuple;

template <typename... Args>
struct DecayTuple<std::tuple<Args...>>
{
    using type = std::tuple<typename std::decay<Args>::type...>;
};

/** @brief Convert T[N] to T* if is_same<Tbase,T>
 *
 *  @tparam Tbase - The base type expected.
 *  @tparam T - The type to convert.
 */
template <typename Tbase, typename T>
using ArrayToPtr_t = typename std::conditional_t<
    std::is_array<T>::value,
    std::conditional_t<std::is_same<Tbase, std::remove_extent_t<T>>::value,
                       std::add_pointer_t<std::remove_extent_t<T>>, T>,
    T>;

/** @brief Downcast type submembers.
 *
 * This allows std::tuple and std::pair members to be downcast to their
 * non-const, nonref versions of themselves to limit duplication in template
 * specializations
 *
 *  1. Remove references.
 *  2. Remove 'const' and 'volatile'.
 *  3. Convert 'char[N]' to 'char*'.
 */
template <typename T>
struct DowncastMembers
{
    using type = T;
};
template <typename... Args>
struct DowncastMembers<std::pair<Args...>>
{
    using type = std::pair<utility::ArrayToPtr_t<
        char, std::remove_cv_t<std::remove_reference_t<Args>>>...>;
};

template <typename... Args>
struct DowncastMembers<std::tuple<Args...>>
{
    using type = std::tuple<utility::ArrayToPtr_t<
        char, std::remove_cv_t<std::remove_reference_t<Args>>>...>;
};

template <typename T>
using DowncastMembers_t = typename DowncastMembers<T>::type;

/** @brief Convert some C++ types to others for 'TypeId' conversion purposes.
 *
 *  Similar C++ types have the same dbus type-id, so 'downcast' those to limit
 *  duplication in TypeId template specializations.
 *
 *  1. Remove references.
 *  2. Remove 'const' and 'volatile'.
 *  3. Convert 'char[N]' to 'char*'.
 */
template <typename T>
struct TypeIdDowncast
{
    using type = utility::ArrayToPtr_t<
        char, DowncastMembers_t<std::remove_cv_t<std::remove_reference_t<T>>>>;
};

template <typename T>
using TypeIdDowncast_t = typename TypeIdDowncast<T>::type;

/** @brief Detect if a type is a tuple
 *
 */
template <typename>
struct is_tuple : std::false_type
{
};

template <typename... T>
struct is_tuple<std::tuple<T...>> : std::true_type
{
};

} // namespace utility

} // namespace ipmi
