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

constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

/** @brief get the D-Bus service and service path
 *  @param[in] bus - The Dbus bus object
 *  @param[in] interface - interface to the service
 *  @param[in] path - interested path in the list of objects
 *  @return pair of service path and service
 */
DbusInfo getDbusInfo(sdbusplus::bus::bus& bus, const std::string& interface,
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
        log<level::ERR>("Error in mapper GetSubTree");
        elog<InternalFailure>();
    }

    MapperResponseType mapperResponse;
    mapperResponseMsg.read(mapperResponse);
    if (mapperResponse.empty())
    {
        log<level::ERR>("Invalid response from mapper");
        elog<InternalFailure>();
    }

    if (path == "")
    {
        //Get the first one if the path is not in list.
        return std::make_pair(mapperResponse.begin()->first,
            mapperResponse.begin()->second.begin()->first);
    }
    const auto& iter = mapperResponse.find(path);
    if(iter == mapperResponse.end())
    {
        log<level::ERR>("Error in finding sensor dbus");
        elog<InternalFailure>();
    }
    return std::make_pair(iter->first, iter->second.begin()->first);
}

using Assertion = uint16_t;
using Deassertion = uint16_t;
using AssertionSet = std::pair<Assertion, Deassertion>;

AssertionSet getAssertionSet(SetSensorReadingReq* cmdData)
{
    Assertion assertionStates =
            (static_cast<Assertion>(cmdData->assertOffset8_14)) << 8 |
            cmdData->assertOffset0_7;
    Deassertion deassertionStates =
            (static_cast<Deassertion>(cmdData->deassertOffset8_14)) << 8 |
            cmdData->deassertOffset0_7;
    return std::make_pair(assertionStates, deassertionStates);
}

ipmi_ret_t updateToDbus(IPMIUpdateData& msg)
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

namespace Set
{

IPMIUpdateData makeDbusMsg(const std::string& updateInterface,
                  const std::string& sensorPath,
                  const std::string& command,
                  const std::string& sensorInterface)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    DbusInfo service;

    std::string dbusService;
    std::string dbusPath;

    std::tie(dbusPath, dbusService) = getDbusInfo(bus,
                                                  sensorInterface,
                                                  sensorPath);
    auto updMsg = bus.new_method_call(dbusService.c_str(),
                                      dbusPath.c_str(),
                                      updateInterface.c_str(),
                                      command.c_str());
    return updMsg;
}

ipmi_ret_t discreteSignal(IPMIUpdateData& msg,
                   const DbusInterfaceMap& interfaceList,
                   uint8_t data)
{
    const auto& interface = interfaceList.begin();
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
    return IPMI_CC_OK;
}

ipmi_ret_t sendData(IPMIUpdateData& msg,
                    const DbusInterfaceMap& interfaceList,
                    Value data)
{
    const auto& interface = interfaceList.begin();
    msg.append(interface->first);
    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        msg.append(data);
    }
    return IPMI_CC_OK;
}

ipmi_ret_t assertion(IPMIUpdateData& msg,
                     const DbusInterfaceMap& interfaceList,
                     const std::string& sensorPath,
                     SetSensorReadingReq* cmdData)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);

    const auto& interface = interfaceList.begin();
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
    return IPMI_CC_OK;
}
}//namespace Set

namespace Notify
{

IPMIUpdateData makeDbusMsg(const std::string& updateInterface,
                  const std::string& sensorPath,
                  const std::string& command,
                  const std::string& sensorInterface)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    DbusInfo service;

    std::string dbusService;
    std::string dbusPath;

    std::tie(dbusPath, dbusService) = getDbusInfo(bus,
                                                  updateInterface);

    auto updMsg = bus.new_method_call(dbusService.c_str(),
                                      dbusPath.c_str(),
                                      updateInterface.c_str(),
                                      command.c_str());
    return updMsg;
}

ipmi_ret_t discreteSignal(IPMIUpdateData& msg, 
                 const DbusInterfaceMap& interfaceList,
                 uint8_t data)
{
    return IPMI_CC_OK;;
}

ipmi_ret_t sendData(IPMIUpdateData& msg, const DbusInterfaceMap& interface, Value data)
{
    return IPMI_CC_OK;
}

ipmi_ret_t assertion(IPMIUpdateData& msg,
                     const DbusInterfaceMap& interfaceList,
                     const std::string& sensorPath,
                     SetSensorReadingReq* cmdData)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);
    ipmi::sensor::ObjectMap objects;
    ipmi::sensor::InterfaceMap interfaces;
    for (const auto& interface : interfaceList)
    {
        for (const auto& property : interface.second)
        {
            ipmi::sensor::PropertyMap props;
            bool valid = false;
            for (const auto& value : property.second)
            {
                if (assertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.assert);
                    valid = true;
                }
                else if (deassertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.deassert);
                    valid = true;
                }
            }
            if (valid)
            {
                interfaces.emplace(interface.first, std::move(props));
            }
        }
    }
    objects.emplace(sensorPath, std::move(interfaces));
    msg.append(std::move(objects));
    return IPMI_CC_OK;
}
}//namespace notify
}//namespace sensor
}//namespace ipmi
