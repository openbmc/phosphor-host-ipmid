/*
// Copyright (c) 2017 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once
#include <algorithm>
#include <cmath>
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
