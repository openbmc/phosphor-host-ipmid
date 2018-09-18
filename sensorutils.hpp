/*
// Copyright (c) 2017 Intel Corporation
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
#include <host-ipmid/ipmid-api.h>

#include <cmath>
#include <iostream>

static constexpr bool DEBUG = false;

namespace ipmi
{
static constexpr int16_t MAX_INT10 = 0x1FF;
static constexpr int16_t MIN_INT10 = -(0x200);
static constexpr int8_t MAX_INT4 = 7;
static constexpr int8_t MIN_INT4 = -8;

inline bool GetSensorAttributes(const double max, const double min,
                                int16_t& mValue, int8_t& rExp, int16_t& bValue,
                                int8_t& bExp, bool& bSigned)
{
    // computing y = (10^rRexp) * (Mx + (B*(10^Bexp)))
    // check for 0, assume always positive
    double mDouble;
    double bDouble;
    if (!(max > min))
    {
        std::cerr << "GetSensorAttributes: Max must be greater than min\n";
        return false;
    }
    else
    {
        mDouble = (max - min) / 0xFF;
    }
    if (!mDouble)
        mDouble = 1;

    if (min < 0)
    {
        bSigned = true;
        bDouble = floor(0.5 + ((max + min) / 2));
    }
    else
    {
        bSigned = false;
        bDouble = min;
    }

    rExp = 0;

    // M too big for 10 bit variable
    while (mDouble > MAX_INT10)
    {
        if (rExp == MAX_INT4)
        {
            std::cerr << "rExp Too big, Max and Min range too far\n";
            return false;
        }
        mDouble /= 10;
        rExp += 1;
    }

    // M too small, loop until we loose less than 1 eight bit count of precision
    while (((mDouble - floor(mDouble)) / mDouble) > (1.0 / 255))
    {
        if (rExp == MIN_INT4)
        {
            std::cerr << "rExp Too Small, Max and Min range too close\n";
            return false;
        }
        // check to see if we reached the limit of where we can adjust back the
        // B value
        if (bDouble / std::pow(10, rExp + MIN_INT4 - 1) > bDouble)
        {
            if (mDouble < 1.0)
            {
                std::cerr << "Could not find mValue and B value with enough "
                             "precision.\n";
                return false;
            }
            break;
        }
        // can't multiply M any more, max precision reached
        else if (mDouble * 10 > MAX_INT10)
        {
            break;
        }
        mDouble *= 10;
        rExp -= 1;
    }

    bDouble /= std::pow(10, rExp);
    bExp = 0;

    // B too big for 10 bit variable
    while (bDouble > MAX_INT10 || bDouble < MIN_INT10)
    {
        if (bExp == MAX_INT4)
        {
            std::cerr
                << "bExp Too Big, Max and Min range need to be adjusted\n";
            return false;
        }
        bDouble /= 10;
        bExp += 1;
    }

    while (((fabs(bDouble) - floor(fabs(bDouble))) / fabs(bDouble)) >
           (1.0 / 255))
    {
        if (bExp == MIN_INT4)
        {
            std::cerr
                << "bExp Too Small, Max and Min range need to be adjusted\n";
            return false;
        }
        bDouble *= 10;
        bExp -= 1;
    }

    mValue = static_cast<int16_t>(mDouble + 0.5) & MAX_INT10;
    bValue = static_cast<int16_t>(bDouble + 0.5) & MAX_INT10;
    if (DEBUG)
    {
        std::cout << "Calculated mValue = " << static_cast<int>(mValue) << "\n";
        std::cout << "Calculated bValue = " << static_cast<int>(bValue) << "\n";
    }

    return true;
}

inline uint8_t ScaleIPMIValueFromDouble(const double value,
                                        const uint16_t mValue,
                                        const int8_t rExp,
                                        const uint16_t bValue,
                                        const int8_t bExp, const bool bSigned)
{
    uint32_t scaledValue =
        (value - (bValue * std::pow(10, bExp) * std::pow(10, rExp))) /
        (mValue * std::pow(10, rExp));
    if (bSigned)
    {
        return static_cast<int8_t>(scaledValue);
    }
    else
    {
        return static_cast<uint8_t>(scaledValue);
    }
}

inline uint8_t getScaledIPMIValue(const double value, const double max,
                                  const double min)
{
    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = 0;
    bool result = 0;

    result = GetSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned);
    if (!result)
    {
        return 0xFF;
    }
    return ScaleIPMIValueFromDouble(value, mValue, rExp, bValue, bExp, bSigned);
}

} // namespace ipmi