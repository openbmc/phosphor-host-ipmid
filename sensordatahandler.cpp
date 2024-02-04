#include "sensordatahandler.hpp"

#include "sensorhandler.hpp"

#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <bitset>
#include <filesystem>
#include <optional>

namespace ipmi
{
namespace sensor
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::error::xyz::openbmc_project::common::InternalFailure;

AssertionSet getAssertionSet(const SetSensorReadingReq& cmdData)
{
    Assertion assertionStates =
        (static_cast<Assertion>(cmdData.assertOffset8_14)) << 8 |
        cmdData.assertOffset0_7;
    Deassertion deassertionStates =
        (static_cast<Deassertion>(cmdData.deassertOffset8_14)) << 8 |
        cmdData.deassertOffset0_7;
    return std::make_pair(assertionStates, deassertionStates);
}

ipmi_ret_t updateToDbus(IpmiUpdateData& msg)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    try
    {
        auto serviceResponseMsg = bus.call(msg);
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Error in D-Bus call", entry("ERROR=%s", e.what()));
        commit<InternalFailure>();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

namespace get
{

SensorName nameParentLeaf(const Info& sensorInfo)
{
    const auto pos = sensorInfo.sensorPath.find_last_of('/');
    const auto leaf = sensorInfo.sensorPath.substr(pos + 1);

    const auto remaining = sensorInfo.sensorPath.substr(0, pos);

    const auto parentPos = remaining.find_last_of('/');
    auto parent = remaining.substr(parentPos + 1);

    parent += "_" + leaf;
    return parent;
}

GetSensorResponse mapDbusToAssertion(const Info& sensorInfo,
                                     const InstancePath& path,
                                     const DbusInterface& interface)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    GetSensorResponse response{};

    enableScanning(&response);

    auto service = ipmi::getService(bus, interface, path);

    const auto& interfaceList = sensorInfo.propertyInterfaces;

    for (const auto& interface : interfaceList)
    {
        for (const auto& property : interface.second)
        {
            auto propValue = ipmi::getDbusProperty(
                bus, service, path, interface.first, property.first);

            for (const auto& value : std::get<OffsetValueMap>(property.second))
            {
                if (propValue == value.second.assert)
                {
                    setOffset(value.first, &response);
                    break;
                }
            }
        }
    }

    return response;
}

GetSensorResponse mapDbusToEventdata2(const Info& sensorInfo)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    GetSensorResponse response{};

    enableScanning(&response);

    auto service = ipmi::getService(bus, sensorInfo.sensorInterface,
                                    sensorInfo.sensorPath);

    const auto& interfaceList = sensorInfo.propertyInterfaces;

    for (const auto& interface : interfaceList)
    {
        for (const auto& property : interface.second)
        {
            auto propValue =
                ipmi::getDbusProperty(bus, service, sensorInfo.sensorPath,
                                      interface.first, property.first);

            for (const auto& value : std::get<OffsetValueMap>(property.second))
            {
                if (propValue == value.second.assert)
                {
                    setReading(value.first, &response);
                    break;
                }
            }
        }
    }

    return response;
}

#ifndef FEATURE_SENSORS_CACHE
GetSensorResponse assertion(const Info& sensorInfo)
{
    return mapDbusToAssertion(sensorInfo, sensorInfo.sensorPath,
                              sensorInfo.sensorInterface);
}

GetSensorResponse eventdata2(const Info& sensorInfo)
{
    return mapDbusToEventdata2(sensorInfo);
}
#else
std::optional<GetSensorResponse> assertion(uint8_t id, const Info& sensorInfo,
                                           const PropertyMap& /*properties*/)
{
    // The assertion may contain multiple properties
    // So we have to get the properties from DBus anyway
    auto response = mapDbusToAssertion(sensorInfo, sensorInfo.sensorPath,
                                       sensorInfo.sensorInterface);

    if (!sensorCacheMap[id].has_value())
    {
        sensorCacheMap[id] = SensorData{};
    }
    sensorCacheMap[id]->response = response;
    return response;
}

std::optional<GetSensorResponse> eventdata2(uint8_t id, const Info& sensorInfo,
                                            const PropertyMap& /*properties*/)
{
    // The eventdata2 may contain multiple properties
    // So we have to get the properties from DBus anyway
    auto response = mapDbusToEventdata2(sensorInfo);

    if (!sensorCacheMap[id].has_value())
    {
        sensorCacheMap[id] = SensorData{};
    }
    sensorCacheMap[id]->response = response;
    return response;
}

#endif // FEATURE_SENSORS_CACHE

} // namespace get

namespace set
{

IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;

    auto dbusService = getService(bus, sensorInterface, sensorPath);

    return bus.new_method_call(dbusService.c_str(), sensorPath.c_str(),
                               updateInterface.c_str(), command.c_str());
}

ipmi_ret_t eventdata(const SetSensorReadingReq&, const Info& sensorInfo,
                     uint8_t data)
{
    auto msg = makeDbusMsg("org.freedesktop.DBus.Properties",
                           sensorInfo.sensorPath, "Set",
                           sensorInfo.sensorInterface);

    const auto& interface = sensorInfo.propertyInterfaces.begin();
    msg.append(interface->first);
    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        const auto& iter = std::get<OffsetValueMap>(property.second).find(data);
        if (iter == std::get<OffsetValueMap>(property.second).end())
        {
            log<level::ERR>("Invalid event data");
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }
        msg.append(iter->second.assert);
    }
    return updateToDbus(msg);
}

ipmi_ret_t assertion(const SetSensorReadingReq& cmdData, const Info& sensorInfo)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);
    auto bothSet = assertionSet ^ deassertionSet;

    const auto& interface = sensorInfo.propertyInterfaces.begin();

    for (const auto& property : interface->second)
    {
        std::optional<Value> tmp;
        for (const auto& value : std::get<OffsetValueMap>(property.second))
        {
            if (bothSet.size() <= value.first || !bothSet.test(value.first))
            {
                // A BIOS shouldn't do this but ignore if they do.
                continue;
            }

            if (assertionSet.test(value.first))
            {
                tmp = value.second.assert;
                break;
            }
            if (deassertionSet.test(value.first))
            {
                tmp = value.second.deassert;
                break;
            }
        }

        if (tmp)
        {
            auto msg = makeDbusMsg("org.freedesktop.DBus.Properties",
                                   sensorInfo.sensorPath, "Set",
                                   sensorInfo.sensorInterface);
            msg.append(interface->first);
            msg.append(property.first);
            msg.append(*tmp);

            auto rc = updateToDbus(msg);
            if (rc)
            {
                return rc;
            }
        }
    }

    return IPMI_CC_OK;
}

} // namespace set

namespace notify
{

IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string&, const std::string& command,
                           const std::string&)
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;

    static const auto dbusPath = "/xyz/openbmc_project/inventory"s;
    std::string dbusService = ipmi::getService(bus, updateInterface, dbusPath);

    return bus.new_method_call(dbusService.c_str(), dbusPath.c_str(),
                               updateInterface.c_str(), command.c_str());
}

ipmi_ret_t assertion(const SetSensorReadingReq& cmdData, const Info& sensorInfo)
{
    auto msg = makeDbusMsg(sensorInfo.sensorInterface, sensorInfo.sensorPath,
                           "Notify", sensorInfo.sensorInterface);

    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);
    ipmi::sensor::ObjectMap objects;
    ipmi::sensor::InterfaceMap interfaces;
    for (const auto& interface : sensorInfo.propertyInterfaces)
    {
        // An interface with no properties - It is possible that the sensor
        // object on DBUS implements a DBUS interface with no properties.
        // Make sure we add the interface to the list if interfaces on the
        // object with an empty property map.
        if (interface.second.empty())
        {
            interfaces.emplace(interface.first, ipmi::sensor::PropertyMap{});
            continue;
        }
        // For a property like functional state the result will be
        // calculated based on the true value of all conditions.
        for (const auto& property : interface.second)
        {
            ipmi::sensor::PropertyMap props;
            bool valid = false;
            auto result = true;
            for (const auto& value : std::get<OffsetValueMap>(property.second))
            {
                if (assertionSet.test(value.first))
                {
                    // Skip update if skipOn is ASSERT
                    if (SkipAssertion::ASSERT == value.second.skip)
                    {
                        return IPMI_CC_OK;
                    }
                    result = result && std::get<bool>(value.second.assert);
                    valid = true;
                }
                else if (deassertionSet.test(value.first))
                {
                    // Skip update if skipOn is DEASSERT
                    if (SkipAssertion::DEASSERT == value.second.skip)
                    {
                        return IPMI_CC_OK;
                    }
                    result = result && std::get<bool>(value.second.deassert);
                    valid = true;
                }
            }
            for (const auto& value :
                 std::get<PreReqOffsetValueMap>(property.second))
            {
                if (assertionSet.test(value.first))
                {
                    result = result && std::get<bool>(value.second.assert);
                }
                else if (deassertionSet.test(value.first))
                {
                    result = result && std::get<bool>(value.second.deassert);
                }
            }
            if (valid)
            {
                props.emplace(property.first, result);
                interfaces.emplace(interface.first, std::move(props));
            }
        }
    }

    objects.emplace(sensorInfo.sensorPath, std::move(interfaces));
    msg.append(std::move(objects));
    return updateToDbus(msg);
}

} // namespace notify

namespace inventory
{

namespace get
{

#ifndef FEATURE_SENSORS_CACHE

GetSensorResponse assertion(const Info& sensorInfo)
{
    namespace fs = std::filesystem;

    fs::path path{ipmi::sensor::inventoryRoot};
    path += sensorInfo.sensorPath;

    return ipmi::sensor::get::mapDbusToAssertion(
        sensorInfo, path.string(),
        sensorInfo.propertyInterfaces.begin()->first);
}

#else

std::optional<GetSensorResponse> assertion(uint8_t id, const Info& sensorInfo,
                                           const PropertyMap& /*properties*/)
{
    // The assertion may contain multiple properties
    // So we have to get the properties from DBus anyway
    namespace fs = std::filesystem;

    fs::path path{ipmi::sensor::inventoryRoot};
    path += sensorInfo.sensorPath;

    auto response = ipmi::sensor::get::mapDbusToAssertion(
        sensorInfo, path.string(),
        sensorInfo.propertyInterfaces.begin()->first);

    if (!sensorCacheMap[id].has_value())
    {
        sensorCacheMap[id] = SensorData{};
    }
    sensorCacheMap[id]->response = response;
    return response;
}

#endif

} // namespace get

} // namespace inventory
} // namespace sensor
} // namespace ipmi
