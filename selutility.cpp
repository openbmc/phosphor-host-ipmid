#include "config.h"

#include "selutility.hpp"

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <charconv>
#include <chrono>
#include <filesystem>
#include <vector>

extern const ipmi::sensor::InvObjectIDMap invSensors;
using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::error::xyz::openbmc_project::common::InternalFailure;

namespace
{

constexpr auto systemEventRecord = 0x02;
constexpr auto generatorID = 0x2000;
constexpr auto eventMsgRevision = 0x04;
constexpr auto assertEvent = 0x00;
constexpr auto deassertEvent = 0x80;
constexpr auto selDataSize = 3;
constexpr auto oemCDDataSize = 9;
constexpr auto oemEFDataSize = 13;

constexpr auto propAdditionalData = "AdditionalData";
constexpr auto propResolved = "Resolved";

constexpr auto strEventDir = "EVENT_DIR";
constexpr auto strGenerateId = "GENERATOR_ID";
constexpr auto strRecordType = "RECORD_TYPE";
constexpr auto strSensorData = "SENSOR_DATA";
constexpr auto strSensorPath = "SENSOR_PATH";

} // namespace

namespace ipmi
{

namespace sel
{

namespace internal
{

inline bool isRecordOEM(uint8_t recordType)
{
    return recordType != systemEventRecord;
}

using entryDataMap = std::map<PropertyName, PropertyType>;

int convert(const std::string_view& str, int base = 10)
{
    int ret = 0;
    std::from_chars(str.data(), str.data() + str.size(), ret, base);
    return ret;
}

// Convert the string to a vector of uint8_t, where the str is formatted as hex
std::vector<uint8_t> convertVec(const std::string_view& str)
{
    std::vector<uint8_t> ret;
    auto len = str.size() / 2;
    ret.reserve(len);
    for (size_t i = 0; i < len; ++i)
    {
        ret.emplace_back(
            static_cast<uint8_t>(convert(str.substr(i * 2, 2), 16)));
    }
    return ret;
}

/** Construct OEM SEL record according to IPMI spec 32.2, 32.3. */
void constructOEMSEL(uint8_t recordType, std::chrono::milliseconds timestamp,
                     const AdditionalData& data, GetSELEntryResponse& record)
{
    auto dataIter = data.find(strSensorData);
    assert(dataIter != data.end());
    auto sensorData = convertVec(dataIter->second);
    if (recordType >= 0xC0 && recordType < 0xE0)
    {
        record.event.oemCD.timeStamp = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(timestamp)
                .count());
        record.event.oemCD.recordType = recordType;
        // The ManufactureID and OEM Defined are packed in the sensor data
        // Fill the 9 bytes of Manufacture ID and oemDefined
        memcpy(&record.event.oemCD.manufacturerID, sensorData.data(),
               std::min(sensorData.size(), static_cast<size_t>(oemCDDataSize)));
    }
    else if (recordType >= 0xE0)
    {
        record.event.oemEF.recordType = recordType;
        // The remaining 13 bytes are the OEM Defined data
        memcpy(&record.event.oemEF.oemDefined, sensorData.data(),
               std::min(sensorData.size(), static_cast<size_t>(oemEFDataSize)));
    }
}

void constructSEL(uint8_t recordType, std::chrono::milliseconds timestamp,
                  const AdditionalData& data, const entryDataMap&,
                  GetSELEntryResponse& record)
{
    if (recordType != systemEventRecord)
    {
        lg2::error("Invalid recordType");
        elog<InternalFailure>();
    }

    // Default values when there is no matched sensor
    record.event.eventRecord.sensorType = 0;
    record.event.eventRecord.sensorNum = 0xFF;
    record.event.eventRecord.eventType = 0;

    auto iter = data.find(strSensorPath);
    assert(iter != data.end());
    const auto& sensorPath = iter->second;
    auto sensorIter = invSensors.find(sensorPath);

    if (sensorIter != invSensors.end())
    {
        // There is a matched sensor
        record.event.eventRecord.sensorType = sensorIter->second.sensorType;
        record.event.eventRecord.sensorNum = sensorIter->second.sensorID;

        iter = data.find(strEventDir);
        assert(iter != data.end());
        auto eventDir = static_cast<uint8_t>(convert(iter->second));
        uint8_t assert = eventDir ? assertEvent : deassertEvent;
        record.event.eventRecord.eventType =
            assert | sensorIter->second.eventReadingType;
    }
    record.event.eventRecord.recordType = recordType;
    record.event.eventRecord.timeStamp = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(timestamp).count());
    iter = data.find(strGenerateId);
    assert(iter != data.end());
    record.event.eventRecord.generatorID =
        static_cast<uint16_t>(convert(iter->second));
    record.event.eventRecord.eventMsgRevision = eventMsgRevision;
    iter = data.find(strSensorData);
    assert(iter != data.end());
    auto sensorData = convertVec(iter->second);
    // The remaining 3 bytes are the sensor data
    memcpy(&record.event.eventRecord.eventData1, sensorData.data(),
           std::min(sensorData.size(), static_cast<size_t>(selDataSize)));
}

GetSELEntryResponse prepareSELEntry(
    const std::string& objPath,
    ipmi::sensor::InvObjectIDMap::const_iterator iter)
{
    GetSELEntryResponse record{};

    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, logEntryIntf, objPath);

    // Read all the log entry properties.
    auto methodCall = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          propIntf, "GetAll");
    methodCall.append(logEntryIntf);

    entryDataMap entryData;
    try
    {
        auto reply = bus.call(methodCall);
        reply.read(entryData);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error in reading logging property entries: {ERROR}",
                   "ERROR", e);
        elog<InternalFailure>();
    }

    // Read Id from the log entry.
    static constexpr auto propId = "Id";
    auto iterId = entryData.find(propId);
    if (iterId == entryData.end())
    {
        lg2::error("Error in reading Id of logging entry");
        elog<InternalFailure>();
    }

    // Read Timestamp from the log entry.
    static constexpr auto propTimeStamp = "Timestamp";
    auto iterTimeStamp = entryData.find(propTimeStamp);
    if (iterTimeStamp == entryData.end())
    {
        lg2::error("Error in reading Timestamp of logging entry");
        elog<InternalFailure>();
    }
    std::chrono::milliseconds chronoTimeStamp(
        std::get<uint64_t>(iterTimeStamp->second));

    bool isFromSELLogger = false;

    // The recordID are with the same offset between different types,
    // so we are safe to set the recordID here
    record.event.eventRecord.recordID =
        static_cast<uint16_t>(std::get<uint32_t>(iterId->second));

    iterId = entryData.find(propAdditionalData);
    if (iterId != entryData.end())
    {
        // Check if it's a SEL from phosphor-sel-logger which shall contain
        // the record ID, etc
        const auto& addData = std::get<AdditionalData>(iterId->second);
        auto recordTypeIter = addData.find(strRecordType);
        if (recordTypeIter != addData.end())
        {
            // It is a SEL from phosphor-sel-logger
            isFromSELLogger = true;
        }
        else
        {
            // Not a SEL from phosphor-sel-logger, it shall have a valid
            // invSensor
            if (iter == invSensors.end())
            {
                lg2::error("System event sensor not found");
                elog<InternalFailure>();
            }
        }
    }

    if (isFromSELLogger)
    {
        // It is expected to be a custom SEL entry
        const auto& addData = std::get<AdditionalData>(iterId->second);
        auto recordType =
            static_cast<uint8_t>(convert(addData.find(strRecordType)->second));
        auto isOEM = isRecordOEM(recordType);
        if (isOEM)
        {
            constructOEMSEL(recordType, chronoTimeStamp, addData, record);
        }
        else
        {
            constructSEL(recordType, chronoTimeStamp, addData, entryData,
                         record);
        }
    }
    else
    {
        record.event.eventRecord.timeStamp = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(chronoTimeStamp)
                .count());

        record.event.eventRecord.recordType = systemEventRecord;
        record.event.eventRecord.generatorID = generatorID;
        record.event.eventRecord.eventMsgRevision = eventMsgRevision;

        record.event.eventRecord.sensorType = iter->second.sensorType;
        record.event.eventRecord.sensorNum = iter->second.sensorID;
        record.event.eventRecord.eventData1 = iter->second.eventOffset;

        // Read Resolved from the log entry.
        auto iterResolved = entryData.find(propResolved);
        if (iterResolved == entryData.end())
        {
            lg2::error("Error in reading Resolved field of logging entry");
            elog<InternalFailure>();
        }

        // Evaluate if the event is assertion or deassertion event
        if (std::get<bool>(iterResolved->second))
        {
            record.event.eventRecord.eventType =
                deassertEvent | iter->second.eventReadingType;
        }
        else
        {
            record.event.eventRecord.eventType = iter->second.eventReadingType;
        }
    }

    return record;
}

} // namespace internal

GetSELEntryResponse convertLogEntrytoSEL(const std::string& objPath)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    static constexpr auto assocIntf =
        "xyz.openbmc_project.Association.Definitions";
    static constexpr auto assocProp = "Associations";

    std::vector<ipmi::Association> assocs;
    try
    {
        auto service = ipmi::getService(bus, assocIntf, objPath);
        auto propValue =
            ipmi::getDbusProperty(bus, service, objPath, assocIntf, assocProp);
        assocs = std::get<std::vector<ipmi::Association>>(propValue);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error in reading Associations interface: {ERROR}", "ERROR",
                   e);
        elog<InternalFailure>();
    }

    /*
     * Check if the log entry has any callout associations, if there is a
     * callout association try to match the inventory path to the corresponding
     * IPMI sensor.
     */
    for (const auto& item : assocs)
    {
        if (std::get<0>(item).compare(CALLOUT_FWD_ASSOCIATION) == 0)
        {
            auto iter = invSensors.find(std::get<2>(item));
            if (iter == invSensors.end())
            {
                iter = invSensors.find(BOARD_SENSOR);
                if (iter == invSensors.end())
                {
                    lg2::error("Motherboard sensor not found");
                    elog<InternalFailure>();
                }
            }

            return internal::prepareSELEntry(objPath, iter);
        }
    }

    // If there are no callout associations link the log entry to system event
    // sensor
    auto iter = invSensors.find(SYSTEM_SENSOR);
    return internal::prepareSELEntry(objPath, iter);
}

std::chrono::seconds getEntryTimeStamp(const std::string& objPath)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    static constexpr auto propTimeStamp = "Timestamp";

    uint64_t timeStamp;
    try
    {
        auto service = ipmi::getService(bus, logEntryIntf, objPath);
        auto propValue = ipmi::getDbusProperty(bus, service, objPath,
                                               logEntryIntf, propTimeStamp);
        timeStamp = std::get<uint64_t>(propValue);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error in reading Timestamp from Entry interface: {ERROR}",
                   "ERROR", e);
        elog<InternalFailure>();
    }

    std::chrono::milliseconds chronoTimeStamp(timeStamp);

    return std::chrono::duration_cast<std::chrono::seconds>(chronoTimeStamp);
}

void readLoggingObjectPaths(ObjectPaths& paths)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    auto depth = 0;
    paths.clear();

    auto mapperCall = bus.new_method_call(mapperBusName, mapperObjPath,
                                          mapperIntf, "GetSubTreePaths");
    mapperCall.append(logBasePath);
    mapperCall.append(depth);
    mapperCall.append(ObjectPaths({logEntryIntf}));

    try
    {
        auto reply = bus.call(mapperCall);
        reply.read(paths);
    }
    catch (const sdbusplus::exception_t& e)
    {
        if (strcmp(e.name(),
                   "xyz.openbmc_project.Common.Error.ResourceNotFound"))
        {
            throw;
        }
    }

    std::sort(paths.begin(), paths.end(),
              [](const std::string& a, const std::string& b) {
                  namespace fs = std::filesystem;
                  fs::path pathA(a);
                  fs::path pathB(b);
                  auto idA = std::stoul(pathA.filename().string());
                  auto idB = std::stoul(pathB.filename().string());

                  return idA < idB;
              });
}

} // namespace sel

} // namespace ipmi
