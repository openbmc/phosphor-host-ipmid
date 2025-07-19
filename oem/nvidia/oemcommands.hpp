/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
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
constexpr auto cmdGetUsbDescription = 0x30;
} // namespace bootstrap_credentials_oem

namespace bios_password
{
constexpr auto cmdSetBiosPassword = 0x36;
constexpr auto cmdGetBiosPassword = 0x37;
} // namespace bios_password
} // namespace ipmi
