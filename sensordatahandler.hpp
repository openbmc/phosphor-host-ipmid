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
                              const std::string& path = "");

/** @brief Make assertion set from input data
 *  @param[in] cmdData - Input sensor data
 *  @return pair of assertion and deassertion set
 */
AssertionSet getAssertionSet(const SetSensorReadingReq& cmdData);

/** @brief send the message to DBus
 *  @param[in] msg - message to send
 *  @return failure status in IPMI error code
 */
ipmi_ret_t updateToDbus(const IpmiUpdateData& msg);

namespace set
{

/** @brief Make a DBus message for a Dbus call
 *  @param[in] updateInterface - Interface name
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] command - command to be executed
 *  @return a dbus message
 */
IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface);

/** @brief Create a message for IPMI assertion
 *  @param[in] msg - Message to add the values
 *  @param[in] interface - sensor interface
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] cmdData - input sensor data
 *  @return a IPMI error code
 */
ipmi_ret_t appendAssertion(IpmiUpdateData& msg,
                           const DbusInterfaceMap& interfaceMap,
                           const std::string& sensorPath,
                           const SetSensorReadingReq& cmdData);

/** @brief Create a message for discrete signal
 *  @param[in] msg - Message to add the values
 *  @param[in] interface - sensor interface
 *  @param[in] data - input discrete sensor data
 *  @return a IPMI error code
 */
ipmi_ret_t appendDiscreteSignalData(IpmiUpdateData& msg,
                                    const DbusInterfaceMap& interfaceMap,
                                    uint8_t data);

/** @brief Create a message for reading data
 *  @param[in] msg - Message to add the values
 *  @param[in] interface - sensor interface
 *  @param[in] data - input sensor data
 *  @return a IPMI error code
 */
ipmi_ret_t appendReadingData(IpmiUpdateData& msg,
                             const DbusInterfaceMap& interfaceMap,
                             const Value &data);

}//namespace set

namespace notify
{

/** @brief Make a DBus message for a Dbus call
 *  @param[in] updateInterface - Interface name
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] command - command to be executed
 *  @return a dbus message
 */
IpmiUpdateData makeDbusMsg(const std::string& updateInterface,
                           const std::string& sensorPath,
                           const std::string& command,
                           const std::string& sensorInterface);

/** @brief Create a message for IPMI asserting
 *  @param[in] msg - Message to add the values
 *  @param[in] interface - sensor interface
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] cmdData - input sensor data
 *  @return a IPMI error code
 */
inline ipmi_ret_t appendDiscreteSignalData(IpmiUpdateData& msg,
        const DbusInterfaceMap& interfaceMap,
        uint8_t data)
{
    return IPMI_CC_OK;
}

/** @brief Create a message for reading data
 *  @param[in] msg - Message to add the values
 *  @param[in] interface - sensor interface
 *  @param[in] data - input sensor data
 *  @return a IPMI error code
 */
inline ipmi_ret_t appendReadingData(IpmiUpdateData& msg,
                                    const DbusInterfaceMap& interfaceMap,
                                    const Value &data)
{
    return IPMI_CC_OK;
}

/** @brief Create a message for IPMI asserting
 *  @param[in] msg - Message to add the values
 *  @param[in] interface - sensor interface
 *  @param[in] sensorPath - Path of the sensor
 *  @param[in] cmdData - input sensor data
 *  @return a IPMI error code
 */
ipmi_ret_t appendAssertion(IpmiUpdateData& msg,
                           const DbusInterfaceMap& interfaceMap,
                           const std::string& sensorPath,
                           const SetSensorReadingReq& cmdData);

}//namespace notify
}//namespace sensor
}//namespace ipmi
