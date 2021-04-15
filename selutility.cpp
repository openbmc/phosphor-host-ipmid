#include "config.h"

#include "selutility.hpp"

#include <charconv>
#include <chrono>
#include <filesystem>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

extern const ipmi::sensor::InvObjectIDMap invSensors;
using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

namespace
{

constexpr auto systemEventRecord = 0x02;

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

/** Parse the entry with format like key=val */
std::pair<std::string, std::string> parseEntry(const std::string& entry)
{
    constexpr auto equalSign = "=";
    auto pos = entry.find(equalSign);
    assert(pos != std::string::npos);
    auto key = entry.substr(0, pos);
    auto val = entry.substr(pos + 1);
    return {key, val};
}

std::map<std::string, std::string>
    parseAdditionalData(const AdditionalData& data)
{
    std::map<std::string, std::string> ret;

    for (const auto& d : data)
    {
        ret.insert(parseEntry(d));
    }
    return ret;
}

uint8_t convert(const std::string_view& str, int base = 10)
{
    int ret;
    std::from_chars(str.data(), str.data() + str.size(), ret, base);
    return static_cast<uint8_t>(ret);
}

// Convert the string to a vector of uint8_t, where the str is formatted as hex
std::vector<uint8_t> convertVec(const std::string_view& str)
{
    std::vector<uint8_t> ret;
    auto len = str.size() / 2;
    ret.reserve(len);
    for (size_t i = 0; i < len; ++i)
    {
        ret.emplace_back(convert(str.substr(i * 2, 2), 16));
    }
    return ret;
}

GetSELEntryResponse
    prepareSELEntry(const std::string& objPath,
                    ipmi::sensor::InvObjectIDMap::const_iterator iter)
{
    GetSELEntryResponse record{};

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, logEntryIntf, objPath);

    // Read all the log entry properties.
    auto methodCall = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          propIntf, "GetAll");
    methodCall.append(logEntryIntf);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading logging property entries");
        elog<InternalFailure>();
    }

    std::map<PropertyName, PropertyType> entryData;
    reply.read(entryData);

    // Read Id from the log entry.
    static constexpr auto propId = "Id";
    auto iterId = entryData.find(propId);
    if (iterId == entryData.end())
    {
        log<level::ERR>("Error in reading Id of logging entry");
        elog<InternalFailure>();
    }

    // Read Timestamp from the log entry.
    static constexpr auto propTimeStamp = "Timestamp";
    auto iterTimeStamp = entryData.find(propTimeStamp);
    if (iterTimeStamp == entryData.end())
    {
        log<level::ERR>("Error in reading Timestamp of logging entry");
        elog<InternalFailure>();
    }
    std::chrono::milliseconds chronoTimeStamp(
        std::get<uint64_t>(iterTimeStamp->second));

    if (iter == invSensors.end())
    {
        // It is expected to be a custom SEL entry
        record.event.oemCD.recordID =
            static_cast<uint16_t>(std::get<uint32_t>(iterId->second));
        static constexpr auto propAdditionalData = "AdditionalData";
        // static constexpr auto strEventDir = "EVENT_DIR";
        // static constexpr auto strGenerateId = "GENERATOR_ID";
        static constexpr auto strRecordType = "RECORD_TYPE";
        static constexpr auto strSensorData = "SENSOR_DATA";
        // static constexpr auto strSensorPath = "SENSOR_PATH";
        iterId = entryData.find(propAdditionalData);
        if (iterId == entryData.end())
        {
            log<level::ERR>("Error finding AdditionalData");
            elog<InternalFailure>();
        }
        const auto& addData = std::get<AdditionalData>(iterId->second);
        auto m = parseAdditionalData(addData);
        auto recordType = convert(m[strRecordType]);
        auto isOEM = isRecordOEM(recordType);
        if (isOEM)
        {
            if (recordType >= 0xC0 && recordType < 0xE0)
            {
                record.event.oemCD.timeStamp = static_cast<uint32_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        chronoTimeStamp)
                        .count());
                record.event.oemCD.recordType = recordType;
                // The ManufactureID and OEM Defined are packed in the sensor
                // data
                auto sensorData = convertVec(m[strSensorData]);
                // Fill the 9 bytes of Manufacture ID and oemDefined
                memcpy(&record.event.oemCD.manufacturerID, sensorData.data(),
                       std::min(sensorData.size(), static_cast<size_t>(9)));
            }
            else if (recordType >= 0xE0)
            {
                // TODO
            }
        }
        else
        {
            // TODO
        }
    }
    else
    {

        record.event.eventRecord.recordID =
            static_cast<uint16_t>(std::get<uint32_t>(iterId->second));
        record.event.eventRecord.timeStamp = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(chronoTimeStamp)
                .count());

        static constexpr auto generatorID = 0x2000;
        static constexpr auto eventMsgRevision = 0x04;

        record.event.eventRecord.recordType = systemEventRecord;
        record.event.eventRecord.generatorID = generatorID;
        record.event.eventRecord.eventMsgRevision = eventMsgRevision;

        record.event.eventRecord.sensorType = iter->second.sensorType;
        record.event.eventRecord.sensorNum = iter->second.sensorID;
        record.event.eventRecord.eventData1 = iter->second.eventOffset;

        // Read Resolved from the log entry.
        static constexpr auto propResolved = "Resolved";
        auto iterResolved = entryData.find(propResolved);
        if (iterResolved == entryData.end())
        {
            log<level::ERR>("Error in reading Resolved field of logging entry");
            elog<InternalFailure>();
        }

        static constexpr auto deassertEvent = 0x80;

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
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    static constexpr auto assocIntf =
        "xyz.openbmc_project.Association.Definitions";
    static constexpr auto assocProp = "Associations";

    auto service = ipmi::getService(bus, assocIntf, objPath);

    // Read the Associations interface.
    auto methodCall =
        bus.new_method_call(service.c_str(), objPath.c_str(), propIntf, "Get");
    methodCall.append(assocIntf);
    methodCall.append(assocProp);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Associations interface");
        elog<InternalFailure>();
    }

    using AssociationList =
        std::vector<std::tuple<std::string, std::string, std::string>>;

    std::variant<AssociationList> list;
    reply.read(list);

    auto& assocs = std::get<AssociationList>(list);

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
                    log<level::ERR>("Motherboard sensor not found");
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
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, logEntryIntf, objPath);

    using namespace std::string_literals;
    static const auto propTimeStamp = "Timestamp"s;

    auto methodCall =
        bus.new_method_call(service.c_str(), objPath.c_str(), propIntf, "Get");
    methodCall.append(logEntryIntf);
    methodCall.append(propTimeStamp);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Timestamp from Entry interface");
        elog<InternalFailure>();
    }

    std::variant<uint64_t> timeStamp;
    reply.read(timeStamp);

    std::chrono::milliseconds chronoTimeStamp(std::get<uint64_t>(timeStamp));

    return std::chrono::duration_cast<std::chrono::seconds>(chronoTimeStamp);
}

void readLoggingObjectPaths(ObjectPaths& paths)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto depth = 0;
    paths.clear();

    auto mapperCall = bus.new_method_call(mapperBusName, mapperObjPath,
                                          mapperIntf, "GetSubTreePaths");
    mapperCall.append(logBasePath);
    mapperCall.append(depth);
    mapperCall.append(ObjectPaths({logEntryIntf}));

    auto reply = bus.call(mapperCall);
    if (reply.is_method_error())
    {
        log<level::INFO>("Error in reading logging entry object paths");
    }
    else
    {
        reply.read(paths);

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
}

} // namespace sel

} // namespace ipmi
