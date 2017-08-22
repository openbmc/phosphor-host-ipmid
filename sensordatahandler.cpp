#include <bitset>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include "types.hpp"
#include "sensordatahandler.hpp"

namespace ipmi
{
namespace sensor
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

static constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
static constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
static constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

/** @brief get the D-Bus service and service path
 *  @param[in] bus - The Dbus bus object
 *  @param[in] interface - interface to the service
 *  @param[in] path - interested path in the list of objects
 *  @return pair of service path and service
 */
ServicePath getServiceAndPath(sdbusplus::bus::bus& bus,
                              const std::string& interface,
                              const std::string& path)
{
    auto depth = 0;
    auto mapperCall = bus.new_method_call(MAPPER_BUSNAME,
                                          MAPPER_PATH,
                                          MAPPER_INTERFACE,
                                          "GetSubTree");
    mapperCall.append("/");
    mapperCall.append(depth);
    mapperCall.append(std::vector<Interface>({interface}));

    auto mapperResponseMsg = bus.call(mapperCall);
    if (mapperResponseMsg.is_method_error())
    {
        log<level::ERR>("Mapper GetSubTree failed",
                        entry("PATH=%s", path),
                        entry("INTERFACE=%s", interface));
        elog<InternalFailure>();
    }

    MapperResponseType mapperResponse;
    mapperResponseMsg.read(mapperResponse);
    if (mapperResponse.empty())
    {
        log<level::ERR>("Invalid mapper response",
                        entry("PATH=%s", path),
                        entry("INTERFACE=%s", interface));
        elog<InternalFailure>();
    }

    if (path.empty())
    {
        //Get the first one if the path is not in list.
        return std::make_pair(mapperResponse.begin()->first,
                              mapperResponse.begin()->second.begin()->first);
    }
    const auto& iter = mapperResponse.find(path);
    if (iter == mapperResponse.end())
    {
        log<level::ERR>("Coudn't find d-bus path",
                        entry("PATH=%s", path),
                        entry("INTERFACE=%s", interface));
        elog<InternalFailure>();
    }
    return std::make_pair(iter->first, iter->second.begin()->first);
}

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
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    try
    {
        auto serviceResponseMsg = bus.call(msg);
        if (serviceResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in D-Bus call");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

namespace set
{

IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;

    std::string dbusService;
    std::string dbusPath;

    std::tie(dbusPath, dbusService) = getServiceAndPath(bus,
                                      sensorInterface,
                                      sensorPath);
    return bus.new_method_call(dbusService.c_str(),
                               dbusPath.c_str(),
                               updateInterface.c_str(),
                               command.c_str());
}

ipmi_ret_t eventdata(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo,
                     uint8_t data)
{
    auto msg = makeDbusMsg(
                   "org.freedesktop.DBus.Properties",
                   sensorInfo.sensorPath,
                   "Set",
                   sensorInfo.sensorInterface);

    const auto& interface = sensorInfo.propertyInterfaces.begin();
    msg.append(interface->first);
    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        const auto& iter = property.second.find(data);
        if (iter == property.second.end())
        {
            log<level::ERR>("Invalid event data");
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }
        msg.append(iter->second.assert);
    }
    return updateToDbus(msg);
}

ipmi_ret_t assertion(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo)
{
    auto msg = makeDbusMsg(
                   "org.freedesktop.DBus.Properties",
                   sensorInfo.sensorPath,
                   "Set",
                   sensorInfo.sensorInterface);

    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);

    const auto& interface = sensorInfo.propertyInterfaces.begin();
    msg.append(interface->first);
    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        for (const auto& value : property.second)
        {
            if (assertionSet.test(value.first))
            {
                msg.append(value.second.assert);
            }
            if (deassertionSet.test(value.first))
            {
                msg.append(value.second.deassert);
            }
        }
    }
    return updateToDbus(msg);
}

}//namespace set

namespace notify
{

IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;

    std::string dbusService;
    std::string dbusPath;

    std::tie(dbusPath, dbusService) = getServiceAndPath(bus,
                                      updateInterface);

    return bus.new_method_call(dbusService.c_str(),
                               dbusPath.c_str(),
                               updateInterface.c_str(),
                               command.c_str());
}

ipmi_ret_t assertion(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo)
{
    auto msg = makeDbusMsg(
                   sensorInfo.sensorInterface,
                   sensorInfo.sensorPath,
                   "Notify",
                   sensorInfo.sensorInterface);

    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);
    ipmi::sensor::ObjectMap objects;
    ipmi::sensor::InterfaceMap interfaces;
    for (const auto& interface : sensorInfo.propertyInterfaces)
    {
        for (const auto& property : interface.second)
        {
            ipmi::sensor::PropertyMap props;
            bool valid = false;
            bool result = true;
            for (const auto& value : property.second)
            {
                if (assertionSet.test(value.first))
                {
                    result = result && value.second.assert.get<bool>();
                    valid = true;
                }
                else if (deassertionSet.test(value.first))
                {
                    result = result && value.second.deassert.get<bool>();
                    valid = true;
                }
            }
            if (valid)
            {
                props.emplace(property.first, result);
                interfaces.emplace(interface.first, std::move(props));
            }
        }
    }

    if(skipUpdate(sensorInfo.skipUpdateMap, cmdData))
    {
        return IPMI_CC_OK; 
    }

    objects.emplace(sensorInfo.sensorPath, std::move(interfaces));
    msg.append(std::move(objects));
    return updateToDbus(msg);
}

bool skipUpdate(const SkipUpdateMap& skipMap,
                const SetSensorReadingReq& cmdData)
{
    if(skipMap.empty())
    {
        return false;
    }

    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);
    
    bool result = false;
    for (const auto& items : skipMap)
    {
        if (items.second)
        {
            result = result || assertionSet.test(items.first);
        }
        else
        {
            result = result || deassertionSet.test(items.first);
        }
    }

    return result;
}
}//namespace notify
}//namespace sensor
}//namespace ipmi
