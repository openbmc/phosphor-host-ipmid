/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <cstdint>

namespace ipmi
{

using Group = uint8_t;
constexpr Group groupNvidia = 0x3C;

namespace bootstrap_credentials_oem
{
constexpr auto cmdGetUsbVendorIdProductId = 0x30;
constexpr auto cmdGetUsbSerialNumber = 0x31;
constexpr auto cmdGetRedfishHostName = 0x32;
constexpr auto cmdGetIpmiChannelRfHi = 0x33;
constexpr auto cmdGetRedfishServiceUUID = 0x34;
constexpr auto cmdGetRedfishServicePort = 0x35;
} // namespace bootstrap_credentials_oem

namespace bios_password
{
constexpr auto cmdSetBiosPassword = 0x36;
constexpr auto cmdGetBiosPassword = 0x37;
} // namespace bios_password
} // namespace ipmi
