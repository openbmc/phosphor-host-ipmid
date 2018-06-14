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

namespace ipmi
{

namespace utility
{

// helper class to remove const and reference from types
template <typename T> struct decay_tuple
{
};

template <typename... Args> struct decay_tuple<std::tuple<Args...>>
{
    using type = std::tuple<typename std::decay<Args>::type...>;
};

/** @brief Convert T[N] to T* if is_same<Tbase,T>
 *
 *  @tparam Tbase - The base type expected.
 *  @tparam T - The type to convert.
 */
template <typename Tbase, typename T>
using array_to_ptr_t = typename std::conditional_t<
    std::is_array<T>::value,
    std::conditional_t<std::is_same<Tbase, std::remove_extent_t<T>>::value,
                       std::add_pointer_t<std::remove_extent_t<T>>, T>,
    T>;

} // namespace utility

namespace message
{

namespace types
{

namespace details
{

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
template <typename T> struct downcast_members
{
    using type = T;
};
template <typename... Args> struct downcast_members<std::pair<Args...>>
{
    using type = std::pair<utility::array_to_ptr_t<
        char, std::remove_cv_t<std::remove_reference_t<Args>>>...>;
};

template <typename... Args> struct downcast_members<std::tuple<Args...>>
{
    using type = std::tuple<utility::array_to_ptr_t<
        char, std::remove_cv_t<std::remove_reference_t<Args>>>...>;
};

template <typename T>
using downcast_members_t = typename downcast_members<T>::type;

/** @brief Convert some C++ types to others for 'type_id' conversion purposes.
 *
 *  Similar C++ types have the same dbus type-id, so 'downcast' those to limit
 *  duplication in type_id template specializations.
 *
 *  1. Remove references.
 *  2. Remove 'const' and 'volatile'.
 *  3. Convert 'char[N]' to 'char*'.
 */
template <typename T> struct type_id_downcast
{
    using type = utility::array_to_ptr_t<
        char, downcast_members_t<std::remove_cv_t<std::remove_reference_t<T>>>>;
};

template <typename T>
using type_id_downcast_t = typename type_id_downcast<T>::type;

} // namespace details

} // namespace types

} // namespace message

} // namespace ipmi
