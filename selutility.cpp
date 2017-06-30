#include "selutility.hpp"
#include "storagehandler.h"
#include "types.hpp"
#include "utils.hpp"
#include "host-ipmid/ipmid-api.h"
#include <vector>

namespace ipmi
{

namespace sel
{

uint32_t getEntryTimeStamp(const std::string& service,
                           const std::string& objPath)
{
    using namespace std::string_literals;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    static const auto intf = "org.freedesktop.DBus.Properties"s;

    auto methodCall = bus.new_method_call(service.c_str(),
                                     objPath.c_str(),
                                     intf.c_str(),
                                     "Get");

    static const auto timeProperty = "Timestamp"s;

    methodCall.append(logEntryIface);
    methodCall.append(timeProperty.c_str());

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        printf("ERROR in reading entry interface for time\n");
    }

    sdbusplus::message::variant<uint64_t> timestamp;
    reply.read(timestamp);

    return static_cast<uint32_t>(sdbusplus::message::variant_ns::get<uint64_t>(timestamp)/1000);
}

extern const ipmi::sensor::InvObjectIDMap invSensors;

GetSELEntryResponse prepareSELEntry(
        const std::string& objPath,
        ipmi::sensor::InvObjectIDMap::const_iterator iter)
{
    struct ipmi::sel::GetSELEntryResponse record {};
    using namespace std::string_literals;

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    static const auto intf = "org.freedesktop.DBus.Properties"s;

    std::string service;

    service = ipmi::getService(bus, logEntryIface, objPath);

    auto methodCall = bus.new_method_call(service.c_str(),
                                         objPath.c_str(),
                                         intf.c_str(),
                                         "Get");

    static const auto idProperty = "Id"s;

    methodCall.append(logEntryIface);
    methodCall.append(idProperty.c_str());

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        throw std::runtime_error("ERROR in reading entry interface for ID");
    }

    sdbusplus::message::variant<uint32_t> logID;
    reply.read(logID);

    methodCall = bus.new_method_call(service.c_str(),
                                     objPath.c_str(),
                                     intf.c_str(),
                                     "Get");

    static const auto timeProperty = "Timestamp"s;

    methodCall.append(logEntryIface);
    methodCall.append(timeProperty.c_str());

    reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        throw std::runtime_error("ERROR in reading entry interface for time");
    }

    sdbusplus::message::variant<uint64_t> timestamp;
    reply.read(timestamp);

    record.recordID = static_cast<uint16_t>(sdbusplus::message::variant_ns::get<uint32_t>(logID));
    record.recordType = systemRecord;
    record.timeStamp = static_cast<uint32_t>(sdbusplus::message::variant_ns::get<uint64_t>(timestamp)/1000);
    record.generatorID = generator;
    record.evmRev = evmRev;
    record.sensorType = iter->second.sensorType;
    record.sensorNum = iter->second.sensorID;
    record.eventType = iter->second.eventReadingType;
    record.eventData1 = iter->second.eventOffset;

    return record;
}

GetSELEntryResponse convertErrorLogtoSEL(const std::string& objPath)
{
    using namespace std::string_literals;

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    static const auto intf = "org.freedesktop.DBus.Properties"s;
    static const auto assocIntf = "org.openbmc.Associations"s;
    static const auto assocProperty = "associations"s;
    static const auto  systemSensor = "/xyz/openbmc_project/inventory/system"s;
    static const auto boardSensor =
            "/xyz/openbmc_project/inventory/system/chassis/motherboard"s;
    std::string service;

    printf("Object Path = %s\n", objPath.c_str());

    service = ipmi::getService(bus, assocIntf, objPath);

    auto methodCall = bus.new_method_call(service.c_str(),
                                         objPath.c_str(),
                                         intf.c_str(),
                                         "Get");

    methodCall.append(assocIntf.c_str());
    methodCall.append(assocProperty.c_str());

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        throw std::runtime_error("ERROR in reading association interface");
    }

    sdbusplus::message::variant<AssociationList> list;
    reply.read(list);

    auto assocs = sdbusplus::message::variant_ns::get<AssociationList>
         (list);
    if (assocs.empty())
    {
        auto iter = invSensors.find(systemSensor);

        if (iter == invSensors.end())
        {
            throw std::runtime_error("System sensor not found");
        }

        return prepareSELEntry(objPath, iter);
    }

    for (const auto& item : assocs)
    {
        if (std::get<0>(item).compare("callout") == 0)
        {
             // Check if the Sensor Number is present
             auto iter = invSensors.find(std::get<2>(item));
             if (iter == invSensors.end())
             {
                 iter = invSensors.find(boardSensor);

             }
             return prepareSELEntry(objPath, iter);
        }
    }

    auto iter = invSensors.find(systemSensor);

    if (iter == invSensors.end())
    {
        throw std::runtime_error("System sensor not found");
    }

    return prepareSELEntry(objPath, iter);
}

} // namespace sel

} // namespace ipmi
