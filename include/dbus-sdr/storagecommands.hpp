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
#include "sensorhandler.hpp"

#include <cstdint>

#define USING_ENTITY_MANAGER_DECORATORS

static constexpr uint8_t ipmiSdrVersion = 0x51;

namespace dynamic_sensors::ipmi::sel
{
static constexpr uint8_t selOperationSupport = 0x02;
static constexpr uint8_t systemEvent = 0x02;
static constexpr size_t systemEventSize = 3;
static constexpr uint8_t oemTsEventFirst = 0xC0;
static constexpr uint8_t oemTsEventLast = 0xDF;
static constexpr size_t oemTsEventSize = 9;
static constexpr uint8_t oemEventFirst = 0xE0;
static constexpr uint8_t oemEventLast = 0xFF;
static constexpr size_t oemEventSize = 13;
static constexpr uint8_t eventMsgRev = 0x04;
} // namespace dynamic_sensors::ipmi::sel

enum class SdrRepositoryInfoOps : uint8_t
{
    allocCommandSupported = 0x1,
    reserveSDRRepositoryCommandSupported = 0x2,
    partialAddSDRSupported = 0x4,
    deleteSDRSupported = 0x8,
    reserved = 0x10,
    modalLSB = 0x20,
    modalMSB = 0x40,
    overflow = 0x80
};

enum class GetFRUAreaAccessType : uint8_t
{
    byte = 0x0,
    words = 0x1
};

enum class SensorUnits : uint8_t
{
    unspecified = 0x0,
    degreesC = 0x1,
    volts = 0x4,
    amps = 0x5,
    watts = 0x6,
    rpm = 0x12,
};

#pragma pack(push, 1)
struct FRUHeader
{
    uint8_t commonHeaderFormat;
    uint8_t internalOffset;
    uint8_t chassisOffset;
    uint8_t boardOffset;
    uint8_t productOffset;
    uint8_t multiRecordOffset;
    uint8_t pad;
    uint8_t checksum;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Type12Record
{
    get_sdr::SensorDataRecordHeader header;
    uint8_t slaveAddress;
    uint8_t channelNumber;
    uint8_t powerStateNotification;
    uint8_t deviceCapabilities;
    // define reserved bytes explicitly. The uint24_t is silently expanded to
    // uint32_t, which ruins the byte alignment required by this structure.
    uint8_t reserved[3];
    uint8_t entityID;
    uint8_t entityInstance;
    uint8_t oem;
    uint8_t typeLengthCode;
    char name[16];

    Type12Record(uint16_t recordID, uint8_t address, uint8_t chNumber,
                 uint8_t pwrStateNotification, uint8_t capabilities,
                 uint8_t eid, uint8_t entityInst, uint8_t mfrDefined,
                 const std::string& sensorname) :
        slaveAddress(address),
        channelNumber(chNumber), powerStateNotification(pwrStateNotification),
        deviceCapabilities(capabilities), reserved{}, entityID(eid),
        entityInstance(entityInst), oem(mfrDefined)
    {
        get_sdr::header::set_record_id(recordID, &header);
        header.sdr_version = ipmiSdrVersion;
        header.record_type = 0x12;
        size_t nameLen = std::min(sensorname.size(), sizeof(name));
        header.record_length = sizeof(Type12Record) -
                               sizeof(get_sdr::SensorDataRecordHeader) -
                               sizeof(name) + nameLen;
        typeLengthCode = 0xc0 | nameLen;
        std::copy(sensorname.begin(), sensorname.begin() + nameLen, name);
    }
};
#pragma pack(pop)

namespace ipmi
{
namespace storage
{

constexpr const size_t type12Count = 2;
ipmi_ret_t getFruSdrs(ipmi::Context::ptr ctx, size_t index,
                      get_sdr::SensorDataFruRecord& resp);

ipmi_ret_t getFruSdrCount(ipmi::Context::ptr ctx, size_t& count);

std::vector<uint8_t>
    getType8SDRs(ipmi::sensor::EntityInfoMap::const_iterator& entity,
                 uint16_t recordId);
std::vector<uint8_t> getType12SDRs(uint16_t index, uint16_t recordId);
std::vector<uint8_t> getNMDiscoverySDR(uint16_t index, uint16_t recordId);
} // namespace storage
} // namespace ipmi
