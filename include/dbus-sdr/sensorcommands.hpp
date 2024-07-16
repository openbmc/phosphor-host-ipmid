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
#include <dbus-sdr/sdrutils.hpp>

#include <cstdint>

#pragma pack(push, 1)

struct SensorThresholdResp
{
    uint8_t readable;
    uint8_t lowernc;
    uint8_t lowercritical;
    uint8_t lowernonrecoverable;
    uint8_t uppernc;
    uint8_t uppercritical;
    uint8_t uppernonrecoverable;
};

#pragma pack(pop)

namespace ipmi
{

uint16_t getNumberOfSensors();

SensorSubTree& getSensorTree();

ipmi_ret_t getSensorConnection(ipmi::Context::ptr ctx, uint8_t sensnum,
                               std::string& connection, std::string& path,
                               std::vector<std::string>* interfaces = nullptr);

struct IPMIThresholds
{
    std::optional<uint8_t> warningLow;
    std::optional<uint8_t> warningHigh;
    std::optional<uint8_t> criticalLow;
    std::optional<uint8_t> criticalHigh;
};

namespace sensor
{
/**
 * @brief Retrieve the number of sensors that are not included in the list of
 * sensors published via D-Bus
 *
 * @param[in]: ctx: the pointer to the D-Bus context
 * @return: The number of additional sensors separate from those published
 * dynamically on D-Bus
 */
size_t getOtherSensorsCount(ipmi::Context::ptr ctx);

/**
 * @brief Retrieve the record data for the sensors not published via D-Bus
 *
 * @param[in]: ctx: the pointer to the D-Bus context
 * @param[in]: recordID: the integer index for the sensor to retrieve
 * @param[out]: SDR data for the indexed sensor
 * @return: 0: success
 *          negative number: error condition
 */
int getOtherSensorsDataRecord(ipmi::Context::ptr ctx, uint16_t recordID,
                              std::vector<uint8_t>& recordData);
} // namespace sensor

namespace dcmi
{

struct sensorInfo
{
    std::string objectPath;
    uint8_t type;
    uint16_t recordId;
    uint8_t entityId;
    uint8_t entityInstance;
};

} // namespace dcmi

} // namespace ipmi
