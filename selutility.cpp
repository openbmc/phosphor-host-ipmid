#include <chrono>
#include <vector>
#include <phosphor-logging/elog-errors.hpp>
#include "host-ipmid/ipmid-api.h"
#include "xyz/openbmc_project/Common/error.hpp"
#include "config.h"
#include "selutility.hpp"
#include "types.hpp"
#include "utils.hpp"

extern const ipmi::sensor::InvObjectIDMap invSensors;
using namespace phosphor::logging;
using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

namespace ipmi
{

namespace sel
{

namespace internal
{

GetSELEntryResponse prepareSELEntry(
        const std::string& objPath,
        ipmi::sensor::InvObjectIDMap::const_iterator iter)
{
    using namespace std::string_literals;
    ipmi::sel::GetSELEntryResponse record {};

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, logEntryIntf, objPath);

    // Read all the log entry properties.
    auto methodCall = bus.new_method_call(service.c_str(),
                                          objPath.c_str(),
                                          propIntf,
                                          "GetAll");
    methodCall.append(logEntryIntf);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading logging property entries");
        elog<InternalFailure>();
    }

    std::map<std::string, PropertyType> entryData;
    reply.read(entryData);

    // Read Id from the log entry.
    static const auto propId = "Id"s;
    auto propIter = entryData.find(propId);

    if (propIter == entryData.end())
    {
        log<level::ERR>("Error in reading Id of logging entry");
        elog<InternalFailure>();
    }

    record.recordID = static_cast<uint16_t>(
            sdbusplus::message::variant_ns::get<uint32_t>(propIter->second));

    // Read Timestamp from the log entry.
    static const auto propTimeStamp = "Timestamp"s;
    propIter = entryData.find(propTimeStamp);

    if (propIter == entryData.end())
    {
        log<level::ERR>("Error in reading Timestamp of logging entry");
        elog<InternalFailure>();
    }

    std::chrono::milliseconds chronoTimeStamp(
            sdbusplus::message::variant_ns::get<uint64_t>(propIter->second));
    record.timeStamp = static_cast<uint32_t>(std::chrono::duration_cast<
            std::chrono::seconds>(chronoTimeStamp).count());

    static constexpr auto systemEventRecord = 0x02;
    static constexpr auto generatorID = 0x2000;
    static constexpr auto eventMsgRevision = 0x04;

    record.recordType = systemEventRecord;
    record.generatorID = generatorID;
    record.eventMsgRevision = eventMsgRevision;

    record.sensorType = iter->second.sensorType;
    record.sensorNum = iter->second.sensorID;
    record.eventData1 = iter->second.eventOffset;

    // Read Resolved from the log entry.
    static const auto propResolved = "Resolved"s;
    propIter = entryData.find(propResolved);
    if (propIter == entryData.end())
    {
        log<level::ERR>("Error in reading Resolved field of logging entry");
        elog<InternalFailure>();
    }

    static constexpr auto deassertEvent = 0x80;

    // Evaluate if the event is assertion or deassertion event
    if (sdbusplus::message::variant_ns::get<bool>(propIter->second))
    {
        record.eventType = deassertEvent | iter->second.eventReadingType;
    }
    else
    {
        record.eventType = iter->second.eventReadingType;
    }

    return record;
}

} // namespace internal

GetSELEntryResponse convertLogEntrytoSEL(const std::string& objPath)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    static constexpr auto assocIntf = "org.openbmc.Associations";
    static constexpr auto assocProp = "associations";

    auto service = ipmi::getService(bus, assocIntf, objPath);


    // Read the Associations interface.
    auto methodCall = bus.new_method_call(service.c_str(),
                                          objPath.c_str(),
                                          propIntf,
                                          "Get");
    methodCall.append(assocIntf);
    methodCall.append(assocProp);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Associations interface");
        elog<InternalFailure>();
    }

    using AssociationList = std::vector<std::tuple<
                            std::string, std::string, std::string>>;

    sdbusplus::message::variant<AssociationList> list;
    reply.read(list);

    auto assocs = sdbusplus::message::variant_ns::get<AssociationList>
         (list);

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
    if (iter == invSensors.end())
    {
        log<level::ERR>("System event sensor not found");
        elog<InternalFailure>();
    }

    return internal::prepareSELEntry(objPath, iter);
}

uint32_t getEntryTimeStamp(const std::string& objPath)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, logEntryIntf, objPath);

    using namespace std::string_literals;
    static const auto propTimeStamp = "Timestamp"s;

    auto methodCall = bus.new_method_call(service.c_str(),
                                          objPath.c_str(),
                                          propIntf,
                                          "Get");
    methodCall.append(logEntryIntf);
    methodCall.append(propTimeStamp);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Timestamp from Entry interface");
        elog<InternalFailure>();
    }

    sdbusplus::message::variant<uint64_t> timeStamp;
    reply.read(timeStamp);

    std::chrono::milliseconds chronoTimeStamp(
            sdbusplus::message::variant_ns::get<uint64_t>(timeStamp));

    return static_cast<uint32_t>(std::chrono::duration_cast<
            std::chrono::seconds>(chronoTimeStamp).count());
}

} // namespace sel

} // namespace ipmi
