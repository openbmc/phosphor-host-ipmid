// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2017,2018 Intel Corporation

#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>

namespace ipmi
{
static constexpr int16_t maxInt10 = 0x1FF;
static constexpr int16_t minInt10 = -0x200;
static constexpr int8_t maxInt4 = 7;
static constexpr int8_t minInt4 = -8;

bool getSensorAttributes(const double max, const double min, int16_t& mValue,
                         int8_t& rExp, int16_t& bValue, int8_t& bExp,
                         bool& bSigned);

uint8_t scaleIPMIValueFromDouble(const double value, const int16_t mValue,
                                 const int8_t rExp, const int16_t bValue,
                                 const int8_t bExp, const bool bSigned);

uint8_t getScaledIPMIValue(const double value, const double max,
                           const double min);
} // namespace ipmi
