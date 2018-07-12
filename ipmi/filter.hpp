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
#include <boost/callable_traits.hpp>
#include <cstdint>
#include <memory>
#include <tuple>
#include <utility>

#include <ipmi/ipmi-api.hpp>
#include <ipmi/message.hpp>


namespace ipmi
{

namespace details
{

using FilterFunction = ipmi::Cc(ipmi::message::Request::ptr);

/**
 * @brief Filter base class for dealing with IPMI request/response
 *
 * The subclasses are all templated so they can provide access to any type of
 * command callback functions.
 */
class FilterBase
{
 public:
  using ptr = std::shared_ptr<FilterBase>;

  virtual ipmi::Cc call(message::Request::ptr request) = 0;
};

/* filter
 *
 * this is the base template that ipmi filters will resolve into
 */
template <typename Filter>
class IpmiFilter : public FilterBase
{
 public:
  IpmiFilter(const Filter&& filter, const std::any&& ctx = std::any())
    : filter_(std::move(filter)), ctx_(std::move(ctx))
  {
  }

  ipmi::Cc call(message::Request::ptr request) override
  {
    return runFilter<Filter>(request);
  }

 private:
  Filter filter_;
  std::any ctx_;

  template <typename T>
  std::enable_if_t<std::is_same<
    boost::callable_traits::args_t<T>,
    boost::callable_traits::args_t<FilterFunction>
      >::value, ipmi::Cc> runFilter(message::Request::ptr request)
  {
    std::cerr << __FUNCTION__ << ':' << __LINE__ << '\n';

    // run the registered filter function and get the ipmi::Cc
    return filter_(request);
  }

  template <typename T>
  std::enable_if_t<!std::is_same<
    boost::callable_traits::args_t<T>,
    boost::callable_traits::args_t<FilterFunction>
      >::value, ipmi::Cc> runFilter(message::Request::ptr request)
  {
    std::cerr << __FUNCTION__ << ':' << __LINE__ << '\n';

    // run the registered filter function and get the ipmi::Cc
    return filter_(request, ctx_);
  }

};

template<typename Filter>
static inline auto makeFilter(const Filter&& filter)
{
  FilterBase::ptr ptr(
      new IpmiFilter<decltype(filter)>(std::forward<Filter>(filter))
    );
  return ptr;
}

template<typename Filter, typename Context>
static inline auto makeFilter(const Filter&& filter, Context& context)
{
  std::any ctx(context);
  FilterBase::ptr ptr(
      new IpmiFilter<decltype(filter)>(std::forward<Filter>(filter, ctx))
    );
  return ptr;
}

} // namespace details

} // namespace ipmi
