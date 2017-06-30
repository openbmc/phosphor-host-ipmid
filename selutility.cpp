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

GetSELEntryResponse prepareSELEntry(
        const std::string& objPath,
        ipmi::sensor::InvObjectIDMap::const_iterator iter)
{
    ipmi::sel::GetSELEntryResponse record {};

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    std::string service;

    try
    {
        service = ipmi::getService(bus, logEntryIntf, objPath);
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        report<InternalFailure>();
    }

    // Read Id from the DBUS logging entry object.
    auto methodCall = bus.new_method_call(service.c_str(),
                                          objPath.c_str(),
                                          propIntf,
                                          "Get");
    methodCall.append(logEntryIntf);
    methodCall.append(propId);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Id from Entry interface");
        report<InternalFailure>();
    }

    sdbusplus::message::variant<uint32_t> logID;
    reply.read(logID);

    // Read Resolved field from the DBUS logging entry object.
    methodCall = bus.new_method_call(service.c_str(),
                                     objPath.c_str(),
                                     propIntf,
                                     "Get");
    methodCall.append(logEntryIntf);
    methodCall.append(propResolved);

    reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Resolved from Entry interface");
        report<InternalFailure>();
    }

    sdbusplus::message::variant<bool> resolved;
    reply.read(resolved);

    // Read Timestamp from the DBUS logging entry object.
    methodCall = bus.new_method_call(service.c_str(),
                                     objPath.c_str(),
                                     propIntf,
                                     "Get");
    methodCall.append(logEntryIntf);
    methodCall.append(propTimeStamp);

    reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Timestamp from Entry interface");
        report<InternalFailure>();
    }

    sdbusplus::message::variant<uint64_t> timeStamp;
    reply.read(timeStamp);

    std::chrono::milliseconds chronoTimeStamp(
            sdbusplus::message::variant_ns::get<uint64_t>(timeStamp));

    record.recordID = static_cast<uint16_t>(
            sdbusplus::message::variant_ns::get<uint32_t>(logID));
    record.recordType = systemEventRecord;
    record.timeStamp = static_cast<uint32_t>(std::chrono::duration_cast<
            std::chrono::seconds>(chronoTimeStamp).count());
    record.generatorID = generatorID;
    record.evmRev = evmRev;
    record.sensorType = iter->second.sensorType;
    record.sensorNum = iter->second.sensorID;
    record.eventData1 = iter->second.eventOffset;

    // Evaluate if the event is assertion or deassertion event
    if (sdbusplus::message::variant_ns::get<bool>(resolved))
    {
        record.eventType = deassertEvent | iter->second.eventReadingType;
    }
    else
    {
        record.eventType = iter->second.eventReadingType;
    }

    return record;
}

GetSELEntryResponse convertLogEntrytoSEL(const std::string& objPath)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    std::string service;

    try
    {
        service = ipmi::getService(bus, assocIntf, objPath);
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        report<InternalFailure>();
    }

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
        report<InternalFailure>();
    }

    sdbusplus::message::variant<AssociationList> list;
    reply.read(list);

    auto assocs = sdbusplus::message::variant_ns::get<AssociationList>
         (list);

    for (const auto& item : assocs)
    {
        if (std::get<0>(item).compare("callout") == 0)
        {
             auto iter = invSensors.find(std::get<2>(item));
             if (iter == invSensors.end())
             {
                 iter = invSensors.find(boardSensor);
                 if (iter == invSensors.end())
                 {
                     log<level::ERR>("Motherboard sensor not found");
                     report<InternalFailure>();
                 }
             }

             return prepareSELEntry(objPath, iter);
        }
    }

    auto iter = invSensors.find(systemSensor);
    if (iter == invSensors.end())
    {
        log<level::ERR>("System event sensor not found");
        report<InternalFailure>();
    }

    return prepareSELEntry(objPath, iter);
}

} // namespace sel

} // namespace ipmi
