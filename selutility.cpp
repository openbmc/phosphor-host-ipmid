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

} // namespace sel

} // namespace ipmi
