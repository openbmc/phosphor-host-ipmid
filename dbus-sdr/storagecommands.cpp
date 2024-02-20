/*
// Copyright (c) 2017-2019 Intel Corporation
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

#include "dbus-sdr/storagecommands.hpp"

#include "dbus-sdr/sdrutils.hpp"
#include "selutility.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/process.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/types.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>

#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>

static constexpr bool DEBUG = false;

namespace ipmi
{
namespace storage
{

constexpr static const char* selLoggerServiceName =
    "xyz.openbmc_project.Logging.IPMI";

ipmi::RspType<uint16_t,                   // Next Record ID
              uint16_t,                   // Record ID
              uint8_t,                    // Record Type
              std::variant<systemEventType, oemTsEventType,
                           oemEventType>> // Record Content
    ipmiStorageGetSELEntry(uint16_t reservationID, uint16_t targetID,
                           uint8_t offset, uint8_t size)
{
    // Only support getting the entire SEL record. If a partial size or non-zero
    // offset is requested, return an error
    if (offset != 0 || size != ipmi::sel::entireRecord)
    {
        return ipmi::responseRetBytesUnavailable();
    }

    // Check the reservation ID if one is provided or required (only if the
    // offset is non-zero)
    if (reservationID != 0 || offset != 0)
    {
        if (!checkSELReservation(reservationID))
        {
            return ipmi::responseInvalidReservationId();
        }
    }

    // Get the ipmi_sel log files
    std::vector<std::filesystem::path> selLogFiles;
    if (!getSELLogFiles(selLogFiles))
    {
        return ipmi::responseSensorInvalid();
    }

    std::string targetEntry;

    if (targetID == ipmi::sel::firstEntry)
    {
        // The first entry will be at the top of the oldest log file
        std::ifstream logStream(selLogFiles.back());
        if (!logStream.is_open())
        {
            return ipmi::responseUnspecifiedError();
        }

        if (!std::getline(logStream, targetEntry))
        {
            return ipmi::responseUnspecifiedError();
        }
    }
    else if (targetID == ipmi::sel::lastEntry)
    {
        // The last entry will be at the bottom of the newest log file
        std::ifstream logStream(selLogFiles.front());
        if (!logStream.is_open())
        {
            return ipmi::responseUnspecifiedError();
        }

        std::string line;
        while (std::getline(logStream, line))
        {
            targetEntry = line;
        }
    }
    else
    {
        if (!findSELEntry(targetID, selLogFiles, targetEntry))
        {
            return ipmi::responseSensorInvalid();
        }
    }

    // The format of the ipmi_sel message is "<Timestamp>
    // <ID>,<Type>,<EventData>,[<Generator ID>,<Path>,<Direction>]".
    // First get the Timestamp
    size_t space = targetEntry.find_first_of(" ");
    if (space == std::string::npos)
    {
        return ipmi::responseUnspecifiedError();
    }
    std::string entryTimestamp = targetEntry.substr(0, space);
    // Then get the log contents
    size_t entryStart = targetEntry.find_first_not_of(" ", space);
    if (entryStart == std::string::npos)
    {
        return ipmi::responseUnspecifiedError();
    }
    std::string_view entry(targetEntry);
    entry.remove_prefix(entryStart);
    // Use split to separate the entry into its fields
    std::vector<std::string> targetEntryFields;
    boost::split(targetEntryFields, entry, boost::is_any_of(","),
                 boost::token_compress_on);
    if (targetEntryFields.size() < 3)
    {
        return ipmi::responseUnspecifiedError();
    }
    std::string& recordIDStr = targetEntryFields[0];
    std::string& recordTypeStr = targetEntryFields[1];
    std::string& eventDataStr = targetEntryFields[2];

    uint16_t recordID;
    uint8_t recordType;
    try
    {
        recordID = std::stoul(recordIDStr);
        recordType = std::stoul(recordTypeStr, nullptr, 16);
    }
    catch (const std::invalid_argument&)
    {
        return ipmi::responseUnspecifiedError();
    }
    uint16_t nextRecordID = getNextRecordID(recordID, selLogFiles);
    std::vector<uint8_t> eventDataBytes;
    if (fromHexStr(eventDataStr, eventDataBytes) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    if (recordType == dynamic_sensors::ipmi::sel::systemEvent)
    {
        // Get the timestamp
        std::tm timeStruct = {};
        std::istringstream entryStream(entryTimestamp);

        uint32_t timestamp = ipmi::sel::invalidTimeStamp;
        if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
        {
            timeStruct.tm_isdst = -1;
            timestamp = std::mktime(&timeStruct);
        }

        // Set the event message revision
        uint8_t evmRev = dynamic_sensors::ipmi::sel::eventMsgRev;

        uint16_t generatorID = 0;
        uint8_t sensorType = 0;
        uint16_t sensorAndLun = 0;
        uint8_t sensorNum = 0xFF;
        uint7_t eventType = 0;
        bool eventDir = 0;
        // System type events should have six fields
        if (targetEntryFields.size() >= 6)
        {
            std::string& generatorIDStr = targetEntryFields[3];
            std::string& sensorPath = targetEntryFields[4];
            std::string& eventDirStr = targetEntryFields[5];

            // Get the generator ID
            try
            {
                generatorID = std::stoul(generatorIDStr, nullptr, 16);
            }
            catch (const std::invalid_argument&)
            {
                std::cerr << "Invalid Generator ID\n";
            }

            // Get the sensor type, sensor number, and event type for the sensor
            sensorType = getSensorTypeFromPath(sensorPath);
            sensorAndLun = getSensorNumberFromPath(sensorPath);
            sensorNum = static_cast<uint8_t>(sensorAndLun);
            if ((generatorID & 0x0001) == 0)
            {
                // IPMB Address
                generatorID |= sensorAndLun & 0x0300;
            }
            else
            {
                // system software
                generatorID |= sensorAndLun >> 8;
            }
            eventType = getSensorEventTypeFromPath(sensorPath);

            // Get the event direction
            try
            {
                eventDir = std::stoul(eventDirStr) ? 0 : 1;
            }
            catch (const std::invalid_argument&)
            {
                std::cerr << "Invalid Event Direction\n";
            }
        }

        // Only keep the eventData bytes that fit in the record
        std::array<uint8_t, dynamic_sensors::ipmi::sel::systemEventSize>
            eventData{};
        std::copy_n(eventDataBytes.begin(),
                    std::min(eventDataBytes.size(), eventData.size()),
                    eventData.begin());

        return ipmi::responseSuccess(
            nextRecordID, recordID, recordType,
            systemEventType{timestamp, generatorID, evmRev, sensorType,
                            sensorNum, eventType, eventDir, eventData});
    }

    if (recordType >= dynamic_sensors::ipmi::sel::oemTsEventFirst &&
        recordType <= dynamic_sensors::ipmi::sel::oemTsEventLast)
    {
        // Get the timestamp
        std::tm timeStruct = {};
        std::istringstream entryStream(entryTimestamp);

        uint32_t timestamp = ipmi::sel::invalidTimeStamp;
        if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
        {
            timeStruct.tm_isdst = -1;
            timestamp = std::mktime(&timeStruct);
        }

        // Only keep the bytes that fit in the record
        std::array<uint8_t, dynamic_sensors::ipmi::sel::oemTsEventSize>
            eventData{};
        std::copy_n(eventDataBytes.begin(),
                    std::min(eventDataBytes.size(), eventData.size()),
                    eventData.begin());

        return ipmi::responseSuccess(nextRecordID, recordID, recordType,
                                     oemTsEventType{timestamp, eventData});
    }

    if (recordType >= dynamic_sensors::ipmi::sel::oemEventFirst)
    {
        // Only keep the bytes that fit in the record
        std::array<uint8_t, dynamic_sensors::ipmi::sel::oemEventSize>
            eventData{};
        std::copy_n(eventDataBytes.begin(),
                    std::min(eventDataBytes.size(), eventData.size()),
                    eventData.begin());

        return ipmi::responseSuccess(nextRecordID, recordID, recordType,
                                     eventData);
    }

    return ipmi::responseUnspecifiedError();
}

/*
Unused arguments
  uint16_t recordID, uint8_t recordType, uint32_t timestamp,
  uint16_t generatorID, uint8_t evmRev, uint8_t sensorType, uint8_t sensorNum,
  uint8_t eventType, uint8_t eventData1, uint8_t eventData2,
  uint8_t eventData3
*/
ipmi::RspType<uint16_t> ipmiStorageAddSELEntry(uint16_t, uint8_t, uint32_t,
                                               uint16_t, uint8_t, uint8_t,
                                               uint8_t, uint8_t, uint8_t,
                                               uint8_t, uint8_t)
{
    // Per the IPMI spec, need to cancel any reservation when a SEL entry is
    // added
    cancelSELReservation();

    uint16_t responseID = 0xFFFF;
    return ipmi::responseSuccess(responseID);
}

ipmi::RspType<uint8_t> ipmiStorageClearSEL(ipmi::Context::ptr ctx,
                                           uint16_t reservationID,
                                           const std::array<uint8_t, 3>& clr,
                                           uint8_t eraseOperation)
{
    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    static constexpr std::array<uint8_t, 3> clrExpected = {'C', 'L', 'R'};
    if (clr != clrExpected)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Erasure status cannot be fetched, so always return erasure status as
    // `erase completed`.
    if (eraseOperation == ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(ipmi::sel::eraseComplete);
    }

    // Check that initiate erase is correct
    if (eraseOperation != ipmi::sel::initiateErase)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is
    // cleared
    cancelSELReservation();

    boost::system::error_code ec;
    ctx->bus->yield_method_call<>(ctx->yield, ec, selLoggerServiceName,
                                  "/xyz/openbmc_project/Logging/IPMI",
                                  "xyz.openbmc_project.Logging.IPMI", "Clear");
    if (ec)
    {
        std::cerr << "error in clear SEL: " << ec << std::endl;
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(ipmi::sel::eraseComplete);
}

void registerStorageFunctions()
{
    createTimers();
    startMatch();

    // <Get FRU Inventory Area Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetFruInventoryAreaInfo,
                          ipmi::Privilege::User, ipmiStorageGetFruInvAreaInfo);
    // <READ FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReadFruData, ipmi::Privilege::User,
                          ipmiStorageReadFruData);

    // <WRITE FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdWriteFruData,
                          ipmi::Privilege::Operator, ipmiStorageWriteFruData);

    // <Get SEL Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSELInfo);

    // <Get SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelEntry, ipmi::Privilege::User,
                          ipmiStorageGetSELEntry);

    // <Add SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdAddSelEntry,
                          ipmi::Privilege::Operator, ipmiStorageAddSELEntry);

    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          ipmiStorageClearSEL);
}
} // namespace storage
} // namespace ipmi
