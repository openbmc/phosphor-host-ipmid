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
#include <filesystem>

#include <cstdint>

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
    uint8_t targetAddress;
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
        targetAddress(address),
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

using systemEventType = std::tuple<
    uint32_t, // Timestamp
    uint16_t, // Generator ID
    uint8_t,  // EvM Rev
    uint8_t,  // Sensor Type
    uint8_t,  // Sensor Number
    uint7_t,  // Event Type
    bool,     // Event Direction
    std::array<uint8_t, dynamic_sensors::ipmi::sel::systemEventSize>>; // Event
                                                                       // Data
using oemTsEventType = std::tuple<
    uint32_t, // Timestamp
    std::array<uint8_t, dynamic_sensors::ipmi::sel::oemTsEventSize>>; // Event
                                                                      // Data
using oemEventType =
    std::array<uint8_t, dynamic_sensors::ipmi::sel::oemEventSize>; // Event Data

constexpr const size_t type12Count = 2;
ipmi_ret_t getFruSdrs(ipmi::Context::ptr ctx, size_t index,
                      get_sdr::SensorDataFruRecord& resp);

ipmi_ret_t getFruSdrCount(ipmi::Context::ptr ctx, size_t& count);

std::vector<uint8_t>
    getType8SDRs(ipmi::sensor::EntityInfoMap::const_iterator& entity,
                 uint16_t recordId);
std::vector<uint8_t> getType12SDRs(uint16_t index, uint16_t recordId);

ipmi::RspType<uint16_t, // inventorySize
              uint8_t>  // accessType
    ipmiStorageGetFruInvAreaInfo(ipmi::Context::ptr ctx, uint8_t fruDeviceId);

ipmi::RspType<uint8_t,             // Count
              std::vector<uint8_t> // Requested data
              >
    ipmiStorageReadFruData(ipmi::Context::ptr ctx, uint8_t fruDeviceId,
                           uint16_t fruInventoryOffset, uint8_t countToRead);

ipmi::RspType<uint8_t>
    ipmiStorageWriteFruData(ipmi::Context::ptr ctx, uint8_t fruDeviceId,
                            uint16_t fruInventoryOffset,
                            std::vector<uint8_t>& dataToWrite);

ipmi::RspType<uint8_t,  // SEL version
              uint16_t, // SEL entry count
              uint16_t, // free space
              uint32_t, // last add timestamp
              uint32_t, // last erase timestamp
              uint8_t>  // operation support
    ipmiStorageGetSELInfo();

bool getSELLogFiles(std::vector<std::filesystem::path>& selLogFiles);
bool findSELEntry(const int recordID,
                  const std::vector<std::filesystem::path>& selLogFiles,
                  std::string& entry);
uint16_t getNextRecordID(const uint16_t recordID,
                         const std::vector<std::filesystem::path>& selLogFiles);
int fromHexStr(const std::string& hexStr, std::vector<uint8_t>& data);
void createTimers();
void startMatch();

} // namespace storage
} // namespace ipmi
