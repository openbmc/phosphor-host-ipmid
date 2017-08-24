#pragma once

#include "types.hpp"
#include "host-ipmid/ipmid-api.h"

namespace ipmi
{
namespace sensor
{

using Assertion = uint16_t;
using Deassertion = uint16_t;
using AssertionSet = std::pair<Assertion, Deassertion>;

using Service = std::string;
using Path = std::string;
using Interface = std::string;

using ServicePath = std::pair<Path, Service>;

using Interfaces = std::vector<Interface>;

using MapperResponseType = std::map<Path, std::map<Service, Interfaces>>;

/** @brief get the D-Bus service and service path
 *  @param[in] bus - The Dbus bus object
 *  @param[in] interface - interface to the service
 *  @param[in] path - interested path in the list of objects
 *  @return pair of service path and service
 */
ServicePath getServiceAndPath(sdbusplus::bus::bus& bus,
                              const std::string& interface,
                              const std::string& path = std::string());

/** @brief Make assertion set from input data
 *  @param[in] cmdData - Input sensor data
 *  @return pair of assertion and deassertion set
 */
AssertionSet getAssertionSet(const SetSensorReadingReq& cmdData);

/** @brief send the message to DBus
 *  @param[in] msg - message to send
 *  @return failure status in IPMI error code
 */
ipmi_ret_t updateToDbus(IpmiUpdateData& msg);

namespace set
{

/** @brief Make a DBus message for a Dbus call
 *  @param[in] updateInterface - Interface name
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] command - command to be executed
 *  @param[in] sensorInterface - DBus interface of sensor
 *  @return a dbus message
 */
IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface);

/** @brief Update d-bus based on assertion type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
ipmi_ret_t assertion(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo);

/** @brief Update d-bus based on a reading assertion
 *  @tparam T - type of d-bus property mapping this sensor
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
template<typename T>
ipmi_ret_t readingAssertion(const SetSensorReadingReq& cmdData,
                            const Info& sensorInfo)
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
        sdbusplus::message::variant<T> value =
            (cmdData.assertOffset8_14 << 8) | cmdData.assertOffset0_7;
        msg.append(value);
    }
    return updateToDbus(msg);
}

/** @brief Update d-bus based on a discrete reading
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return an IPMI error code
 */
template<typename T>
ipmi_ret_t readingData(const SetSensorReadingReq& cmdData,
                       const Info& sensorInfo)
{
    auto msg = makeDbusMsg(
                   "org.freedesktop.DBus.Properties",
                   sensorInfo.sensorPath,
                   "Set",
                   sensorInfo.sensorInterface);

    const auto& interface = sensorInfo.propertyInterfaces.begin();
    msg.append(interface->first);

    ipmi::sensor::Multiplier m = sensorInfo.coefficientM;
    if (0 == m)
    {
        m = 1;  // Avoid * 0
    }

    // TODO: Refactor this into a generated function depending on the type
    // of conversion for the value between IPMI and dbus.
    T raw_value = (m * cmdData.reading) + sensorInfo.scaledOffset;

    for (const auto& property : interface->second)
    {
        msg.append(property.first);
        sdbusplus::message::variant<T> value = raw_value;
        msg.append(value);
    }
    return updateToDbus(msg);
}

/** @brief Update d-bus based on eventdata type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
ipmi_ret_t eventdata(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo,
                     uint8_t data);

/** @brief Update d-bus based on eventdata1 type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
inline ipmi_ret_t eventdata1(const SetSensorReadingReq& cmdData,
                             const Info& sensorInfo)
{
    return eventdata(cmdData, sensorInfo, cmdData.eventData1);
}

/** @brief Update d-bus based on eventdata2 type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
inline ipmi_ret_t eventdata2(const SetSensorReadingReq& cmdData,
                             const Info& sensorInfo)
{
    return eventdata(cmdData, sensorInfo, cmdData.eventData2);
}

/** @brief Update d-bus based on eventdata3 type sensor data
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
inline ipmi_ret_t eventdata3(const SetSensorReadingReq& cmdData,
                             const Info& sensorInfo)
{
    return eventdata(cmdData, sensorInfo, cmdData.eventData3);
}

}//namespace set

namespace notify
{

/** @brief Make a DBus message for a Dbus call
 *  @param[in] updateInterface - Interface name
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] command - command to be executed
 *  @param[in] sensorInterface - DBus interface of sensor
 *  @return a dbus message
 */
IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface);

/** @brief Update d-bus based on assertion type sensor data
 *  @param[in] interfaceMap - sensor interface
 *  @param[in] cmdData - input sensor data
 *  @param[in] sensorInfo - sensor d-bus info
 *  @return a IPMI error code
 */
ipmi_ret_t assertion(const SetSensorReadingReq& cmdData,
                     const Info& sensorInfo);

}//namespace notify
}//namespace sensor
}//namespace ipmi
