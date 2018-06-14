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

/*
 * for dealing with non-integral-byte-sized types
 *
static inline size_t blockRound(size_t sz, size_t blk)
{
  return ((sz) + (((blk) - ((sz) & ((blk) - 1))) & ((blk) - 1)));
}
*/

struct Context
{
  using ptr = std::shared_ptr<Context>;

  int msg_id;
  int channel;
  int userid;
  int privilege;
  int netfn;
  int cmd;
  // TODO VM: what about user context -- legacy's void*?
};

// forward declare message class
namespace message
{

namespace details
{

template <typename A> struct unpack_single;

template <typename T>
using unpack_single_t = unpack_single<types::details::type_id_downcast_t<T>>;

template <typename A> struct pack_single;

template <typename T>
using pack_single_t = pack_single<types::details::type_id_downcast_t<T>>;

} // namespace details

struct Response
{
  /* Define all of the basic class operations:
   *     Not allowed:
   *         - Default constructor to avoid nullptrs.
   *         - Copy operations due to internal unique_ptr.
   *     Allowed:
   *         - Move operations.
   *         - Destructor.
  Response() = delete;
  Response(const Response&) = delete;
  Response& operator=(const Response&) = delete;
  Response(Response&&) = default;
  Response& operator=(Response&&) = default;
  ~Response() = default;
   */

  using ptr = std::shared_ptr<Response>;

  explicit Response(Context::ptr& context, const uint64_t& msgId)
    : ctx(context), bits(0), msgId(msgId) {}

  // base empty pack
  int pack()
  {
    return 0;
  }

  template <typename Arg, typename... Args>
  int pack(Arg&& arg, Args&&... args)
  {
    // std::cerr << __PRETTY_FUNCTION__ << '\n';
    int packRet = details::pack_single_t<Arg>::op(*this,
        std::forward<Arg>(arg));
    if (packRet)
    {
      return packRet;
    }
    // std::cerr << " -> " << arg << '\n';
    return pack(std::forward<Args>(args)...);
  }

  template <typename... Types>
  int pack(std::tuple<Types...>& t)
  {
    return std::apply([this](Types&...args) { return pack(args...); }, t);
  }

  template <typename T>
  void append(T* begin, T* end)
  {
    raw.insert(raw.end(), reinterpret_cast<const uint8_t*>(begin),
        reinterpret_cast<const uint8_t*>(end));
    bits += (end - begin) * 8;
  }

  /** @brief Get the transaction cookie of a message.
   *
   * @return The transaction cookie of a message.
   */
  uint64_t getID() const
  {
    return msgId;
  }

  Context::ptr ctx;
  std::vector<uint8_t> raw;
  size_t bits;
  const uint64_t msgId;
};

struct Request
{
  /* Define all of the basic class operations:
   *     Not allowed:
   *         - Default constructor to avoid nullptrs.
   *         - Copy operations due to internal unique_ptr.
   *     Allowed:
   *         - Move operations.
   *         - Destructor.
  Request() = delete;
  Request(const Request&) = delete;
  Request& operator=(const Request&) = delete;
  Request(Request&&) = default;
  Request& operator=(Request&&) = default;
  ~Request() = default;
   */

  using ptr = std::shared_ptr<Request>;

  explicit Request(Context::ptr context, std::vector<uint8_t>& d,
      const uint64_t& id)
    : ctx(context), raw(d), bits(0), msgId(id) {};

  // base empty unpack
  int unpack()
  {
    return 0;
  }

  template <typename Arg, typename... Args>
  int unpack(Arg&& arg, Args&&... args)
  {
    // std::cerr << __PRETTY_FUNCTION__ << '\n';
    int unpackRet = details::unpack_single_t<Arg>::op(*this,
        std::forward<Arg>(arg));
    if (unpackRet)
    {
      return unpackRet;
    }
    // std::cerr << " -> " << arg << '\n';
    return unpack(std::forward<Args>(args)...);
  }

  template <typename... Types>
  int unpack(std::tuple<Types...>& t)
  {
    int unpack_ok = std::apply([this](Types&...args)
        { return unpack(args...); }, t);
    if (ipmi::ccSuccess == unpack_ok)
    {
      if (raw.size() * 8 == bits)
      {
        // all bits were consumed by requested parameters
        return ipmi::ccSuccess;
      }
      return ipmi::ccReqDataLenInvalid;
    }
    return unpack_ok;
  }

  template <typename T>
  auto pop(size_t nr_bytes)
  {
    if (nr_bytes <= (raw.size() - bits / 8))
    {
      auto range = std::make_tuple(
          reinterpret_cast<T*>(raw.data() + bits / 8),
          reinterpret_cast<T*>(raw.data() + bits / 8 + nr_bytes)
          );
      bits += 8 * nr_bytes;
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
    return std::make_shared<Response>(ctx, msgId);
  }

  /** @brief Get the transaction cookie of a message.
   *
   * @return The transaction cookie of a message.
   */
  uint64_t getID() const
  {
    return msgId;
  }

  Context::ptr ctx;
  std::vector<uint8_t> raw;
  size_t bits;
  const uint64_t msgId;
};

} // namespace message

} // namespace ipmi

// include packing and unpacking of types
#include <ipmi/message/pack.hpp>
#include <ipmi/message/unpack.hpp>
