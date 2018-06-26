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
#include <algorithm>
#include <cstdint>
#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>
#include <ipmi/message/types.hpp>

namespace ipmi
{

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

/** block_round
 *
 * @brief Round up to the next block size (base-2 block sizes only)
 *
 * @arg val the value to round up to the next block size
 * @arg blkSz the block size for rounding (base-2 only)
 *
 * @return the value rounded up
 */
static inline size_t blockRound(size_t val, size_t blkSz)
{
  return ((val) + (((blkSz) - ((val) & ((blkSz) - 1))) & ((blkSz) - 1)));
}

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
    : ctx(context), msgId(msgId) {}

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
    packRet = pack(std::forward<Args>(args)...);
    drain();
    return packRet;
  }

  template <typename... Types>
  int pack(std::tuple<Types...>& t)
  {
    return std::apply([this](Types&...args) { return pack(args...); }, t);
  }

  template <typename T>
  void append(T* begin, T* end)
  {
    // this interface only allows full-byte access; pack in partial bytes
    drain();
    raw.insert(raw.end(), reinterpret_cast<const uint8_t*>(begin),
        reinterpret_cast<const uint8_t*>(end));
  }

  /** @brief Get the transaction cookie of a message.
   *
   * @return The transaction cookie of a message.
   */
  uint64_t getID() const
  {
    return msgId;
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
  void drain(bool wholeBytesOnly=false)
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
    : ctx(context), raw(d), rawIndex(0), bitStream(0), bitCount(0), msgId(id)
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
          reinterpret_cast<T*>(raw.data() + rawIndex + count)
          );
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

  /** @brief fill bit stream with at least count bits for consumption
   *
   * @param[in] count - number of bit needed
   * @return - 0 on success
   */
  int fillBits(size_t count)
  {
    // TODO: this could lose up to 7 bits...
    // think of the time where they request 64 bits but we only have 63 in the
    // stream. We pop one more byte to fill the stream and lose 7 bits.  64 is
    // a nice large number of bits, but if we limit the max requestable bits to
    // be 56, then we avoid this 7 bit loss nonsense.
    if (count > (sizeof(bitStream) - 1)*CHAR_BIT)
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
        //std::cerr << "ran out of bytes to add to the bit stream (raw.size() = " << raw.size() << ")\n";
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

  Context::ptr ctx;
  std::vector<uint8_t> raw;
  size_t rawIndex;
  uint64_t bitStream;
  size_t bitCount;
  const uint64_t msgId;
};

} // namespace message

} // namespace ipmi

// include packing and unpacking of types
#include <ipmi/message/pack.hpp>
#include <ipmi/message/unpack.hpp>
