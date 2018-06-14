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
#include <iostream>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#if __has_include(<optional>)
#include <optional>
#elif __has_include(<experimental/optional>)
#include <experimental/optional>
namespace std {
  // splice experimental::optional into std
  using std::experimental::optional;
  using std::experimental::make_optional;
  using std::experimental::nullopt;
}
#else
#  error optional not available
#endif

#include <boost/callable_traits.hpp>
#include <ipmi/message/types.hpp>
#include <ipmi/ipmi-api.hpp>
#include <ipmi/message.hpp>
#include <ipmi/handler.hpp>


auto ipmiGetDeviceId() ->
  ipmi::RspType<
    ipmi::Cc, // CC
    uint8_t,  // Device ID
    uint8_t,  // Device Revision
    uint8_t,  // Firmware Revision Major
    uint8_t,  // Firmware Revision minor
    uint8_t,  // IPMI version
    uint8_t,  // Additional device support
    uint8_t,  // MFG ID LSB
    uint8_t,  // MFG ID 2
    uint8_t,  // MFG ID MSB
    uint16_t, // Product ID
    uint32_t // AUX info
    >
{
  std::cerr << __FUNCTION__ << '\n';
  return ipmi::response(
      ipmi::ccSuccess,
      uint8_t(0x83),
      uint8_t(0x22),
      uint8_t(0x01),
      uint8_t(0x23),
      uint8_t(2),
      uint8_t(0xff),
      uint8_t(0x57),
      uint8_t(0x01),
      uint8_t(0x00),
      uint16_t(0x01b4),
      uint32_t(0x23a4b79)
      );
}

auto always_invalid() ->
  ipmi::RspType<ipmi::Cc>
{
  std::cerr << __PRETTY_FUNCTION__ << '\n';
  ipmi::Cc cc = ipmi::ccInvalidFieldRequest;
  return ipmi::response(cc);
}

auto sometimes_invalid(uint8_t invalid)
  -> ipmi::RspType<ipmi::Cc, uint8_t, uint8_t>
{
  std::cerr << __PRETTY_FUNCTION__ << ": invalid = " << int(invalid) << '\n';
  if (invalid)
  {
    ipmi::Cc cc = ipmi::ccInvalidFieldRequest;
    return ipmi::response(cc);
  }
  return ipmi::response(ipmi::ccSuccess, uint8_t(0x22), uint8_t(0x07));
}

auto print_values(uint16_t u16, const std::string& s,
    uint32_t u32, uint8_t u8, double d)
{
  std::cerr << __PRETTY_FUNCTION__ << '\n';
  std::cerr << std::hex
    << "u16 = " << u16
    << "\ns = (" << s.length() << ")'" << s
    << "'\nu32 = " << u32
    << "\nu8 = " << int(u8)
    << "\nd = " << d
    << "\n";
  // return std::make_tuple(uint8_t(0), 'a', uint8_t(0x9f), uint16_t(0xbeef),
  //        uint32_t(0xd00dfeed), double(2.71828182845904523536028747135));
  return ipmi::response(ipmi::ccSuccess, u16, s, u32, u8, d);
}


ipmi_ret_t ipmiLegacyGetDeviceID(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
    ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t len, ipmi_context_t ctx)
{
  std::cerr << __PRETTY_FUNCTION__ << '\n';
  std::array<uint8_t, 15> id = {{
      0x83, 0x22, 0x01, 0x23, 0x02, 0xff, 0x57, 0x01,
      0x00, 0xb4, 0x01, 0x79, 0x4b, 0x3a, 0x02 }};
  if (*len > 0)
  {
    return 0xcc;
  }
  std::copy(id.begin(), id.end(), reinterpret_cast<uint8_t*>(response));
  *len = id.size();
  return 0;
}

int main()
{
  uint64_t id = 42;
  {
    std::vector<uint8_t> in{0};
    auto request =
      std::make_shared<ipmi::message::Request>(
          std::make_shared<ipmi::Context>(), in, id++);
    auto handler = ipmi::makeHandler(always_invalid);
    auto response = handler->call(request);
    std::cerr << std::hex;
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
  }

  {
    std::vector<uint8_t> in{0};
    auto request =
      std::make_shared<ipmi::message::Request>(
          std::make_shared<ipmi::Context>(), in, id++);
    auto handler = ipmi::makeHandler(sometimes_invalid);
    auto response = handler->call(request);
    std::cerr << std::hex;
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
    request->raw[0] = 1;
    request->bits = 0;
    response = handler->call(request);
    std::cerr << std::hex;
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
  }

  {
    std::vector<uint8_t> in{ 0x0d, 0xf0, 8, 'A', 'a', 'r', 'd', 'v', 'a', 'r',
      'K', 0xef, 0xbe, 0xad, 0xde, 0x42, 0x18, 0x2d, 0x44, 0x54, 0xfb, 0x21,
      0x09, 0x40 };
    auto request =
      std::make_shared<ipmi::message::Request>(
          std::make_shared<ipmi::Context>(), in, id++);
    auto handler = ipmi::makeHandler(print_values);
    auto response = handler->call(request);
    std::cerr << std::hex;
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
    if (!std::equal(in.begin(), in.end(),
          response->raw.begin() + 1, response->raw.end()))
    {
      std::cerr << "print_values result does not match input as expected\n";
    }
  }

  {
    std::vector<uint8_t> in{};
    auto request =
      std::make_shared<ipmi::message::Request>(
          std::make_shared<ipmi::Context>(), in, id++);
    auto handler = ipmi::makeHandler(ipmiGetDeviceId);
    auto response = handler->call(request);
    std::cerr << std::hex;
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
    std::vector<uint8_t> out = { 0x83, 0x22, 0x01, 0x23, 0x02, 0xff, 0x57,
      0x01, 0x00, 0xb4, 0x01, 0x79, 0x4b, 0x3a, 0x02 };
    if (!std::equal(out.begin(), out.end(),
          response->raw.begin() + 1, response->raw.end()))
    {
      std::cerr << "ipmiGetDeviceId result does not match expected\n";
    }
  }

  {
    std::vector<uint8_t> in{};
    auto request =
      std::make_shared<ipmi::message::Request>(
          std::make_shared<ipmi::Context>(), in, id++);
    auto handler = ipmi::makeHandler(ipmiLegacyGetDeviceID);
    auto response = handler->call(request);
    std::cerr << std::hex;
    for (auto r : response->raw)
    {
      std::cerr << (int)r << ' ';
    }
    std::cerr << '\n';
    std::vector<uint8_t> out = { 0x83, 0x22, 0x01, 0x23, 0x02, 0xff, 0x57,
      0x01, 0x00, 0xb4, 0x01, 0x79, 0x4b, 0x3a, 0x02 };
    if (!std::equal(out.begin(), out.end(),
          response->raw.begin() + 1, response->raw.end()))
    {
      std::cerr << "ipmiLegacyGetDeviceID result does not match expected\n";
    }
  }

  return 0;
}
