#include <chrono>
#include <vector>
#include <phosphor-logging/elog-errors.hpp>
#include "host-ipmid/ipmid-api.h"
#include "xyz/openbmc_project/Common/error.hpp"
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
    static constexpr auto propId = "Id";
    auto iterId = entryData.find(propId);
    if (iterId == entryData.end())
    {
        log<level::ERR>("Error in reading Id of logging entry");
        elog<InternalFailure>();
    }

    record.recordID = static_cast<uint16_t>(
            sdbusplus::message::variant_ns::get<uint32_t>(iterId->second));

    // Read Timestamp from the log entry.
    static constexpr auto propTimeStamp = "Timestamp";
    auto iterTimeStamp = entryData.find(propTimeStamp);
    if (iterTimeStamp == entryData.end())
    {
        log<level::ERR>("Error in reading Timestamp of logging entry");
        elog<InternalFailure>();
    }

    std::chrono::milliseconds chronoTimeStamp(
            sdbusplus::message::variant_ns::get<uint64_t>
            (iterTimeStamp->second));
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
    static constexpr auto propResolved = "Resolved";
    auto iterResolved = entryData.find(propResolved);
    if (iterResolved == entryData.end())
    {
        log<level::ERR>("Error in reading Resolved field of logging entry");
        elog<InternalFailure>();
    }

    static constexpr auto deassertEvent = 0x80;

    // Evaluate if the event is assertion or deassertion event
    if (sdbusplus::message::variant_ns::get<bool>(iterResolved->second))
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

} // namespace sel

} // namespace ipmi
