#pragma once

#include <chrono>
#include <ipmid/api-types.hpp>
#include <ipmid/types.hpp>
#include <optional>
#include <sdbusplus/server.hpp>
#include <map>

namespace ipmi
{

using namespace std::literals::chrono_literals;

constexpr auto MAPPER_BUS_NAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_OBJ = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTF = "xyz.openbmc_project.ObjectMapper";

constexpr auto ROOT = "/";
constexpr auto HOST_MATCH = "host0";

constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";
constexpr auto DELETE_INTERFACE = "xyz.openbmc_project.Object.Delete";

constexpr auto METHOD_GET = "Get";
constexpr auto METHOD_GET_ALL = "GetAll";
constexpr auto METHOD_SET = "Set";

/* Use a value of 5s which aligns with BT/KCS bridged timeouts, rather
 * than the default 25s D-Bus timeout. */
constexpr std::chrono::microseconds IPMI_DBUS_TIMEOUT = 5s;

/** @class ServiceCache
 *  @brief Caches lookups of service names from the object mapper.
 *  @details Most ipmi commands need to talk to other dbus daemons to perform
 *           their intended actions on the BMC. This usually means they will
 *           first look up the service name providing the interface they
 *           require. This class reduces the number of such calls by caching
 *           the lookup for a specific service.
 */
class ServiceCache
{
  public:
    /** @brief Creates a new service cache for the given interface
     *         and path.
     *
     *  @param[in] intf - The interface used for each lookup
     *  @param[in] path - The path used for each lookup
     */
    ServiceCache(const std::string& intf, const std::string& path);
    ServiceCache(std::string&& intf, std::string&& path);

    /** @brief Gets the service name from the cache or does in a
     *         lookup when invalid.
     *
     *  @param[in] bus - The bus associated with and used for looking
     *                   up the service.
     */
    const std::string& getService(sdbusplus::bus::bus& bus);

    /** @brief Invalidates the current service name */
    void invalidate();

    /** @brief A wrapper around sdbusplus bus.new_method_call
     *
     *  @param[in] bus - The bus used for calling the method
     *  @param[in] intf - The interface containing the method
     *  @param[in] method - The method name
     *  @return The message containing the method call.
     */
    sdbusplus::message::message newMethodCall(sdbusplus::bus::bus& bus,
                                              const char* intf,
                                              const char* method);

    /** @brief Check to see if the current cache is valid
     *
     * @param[in] bus - The bus used for the service lookup
     * @return True if the cache is valid false otherwise.
     */
    bool isValid(sdbusplus::bus::bus& bus) const;

  private:
    /** @brief DBUS interface provided by the service */
    const std::string intf;
    /** @brief DBUS path provided by the service */
    const std::string path;
    /** @brief The name of the service if valid */
    std::optional<std::string> cachedService;
    /** @brief The name of the bus used in the service lookup */
    std::optional<std::string> cachedBusName;
};

/**
 *  @class SensorServiceCache
 *  @brief Caches lookups of service names corresponding to sensor paths.
 *  @details A sensor has a sensor path and a service name. For example,
 *           path "/xyz/openbmc_project/sensors/temperature/cpu0temp"
 *           maps to "xyz.openbmc_project.Hwmon-123456789.Hwmon1".
 *           During a call to readingData(), the service name must be
 *           known by calling getService(), such that ipmid can use the
 *           service name to fetch the reading for the sensor being read.
 *           This class caches calls to getService() for all sensors
 *           accessed in readingData().
 */
class SensorServiceCache
{
  public:
    /** @brief Creates a new sensor service cache for all sensors. The cache
     *         is initially empty.
     */
    SensorServiceCache();
    
    /** @brief Gets the service name that corresponds to a sensor path. 
     *         If the service name has not been cached, this function will call
     *         getService() and cache the name. Otherwise the cached name is
     *         returned.
     */
    const std::string& getService(sdbusplus::bus::bus& bus,
                                  const ipmi::sensor::Info& sensorInfo);
    
    /** @brief Invalidates all cached sensor names. */
    void invalidateAll();
    
  private:
    /** @brief The mapping from sensor path to service name */
    std::map<std::string, std::string> cachedServices;
     
    /** @brief The mapping from sensor name to sensor interface. This map
     *         is used to determine any changes in a sensor's interface
     *         name.
     */
    std::map<std::string, std::string> sensorInterfaces;
};

/**
 * @brief Get the DBUS Service name for the input dbus path
 *
 * @param[in] bus - DBUS Bus Object
 * @param[in] intf - DBUS Interface
 * @param[in] path - DBUS Object Path
 *
 */
std::string getService(sdbusplus::bus::bus& bus, const std::string& intf,
                       const std::string& path);

/** @brief Gets the dbus object info implementing the given interface
 *         from the given subtree.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] interface - Dbus interface.
 *  @param[in] subtreePath - subtree from where the search should start.
 *  @param[in] match - identifier for object.
 *  @return On success returns the object having objectpath and servicename.
 */
DbusObjectInfo getDbusObject(sdbusplus::bus::bus& bus,
                             const std::string& interface,
                             const std::string& subtreePath = ROOT,
                             const std::string& match = {});

/** @brief Gets the value associated with the given object
 *         and the interface.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @return On success returns the value of the property.
 */
Value getDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                      const std::string& objPath, const std::string& interface,
                      const std::string& property,
                      std::chrono::microseconds timeout = IPMI_DBUS_TIMEOUT);

/** @brief Gets all the properties associated with the given object
 *         and the interface.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @return On success returns the map of name value pair.
 */
PropertyMap
    getAllDbusProperties(sdbusplus::bus::bus& bus, const std::string& service,
                         const std::string& objPath,
                         const std::string& interface,
                         std::chrono::microseconds timeout = IPMI_DBUS_TIMEOUT);

/** @brief Gets all managed objects associated with the given object
 *         path and service.
 *  @param[in] bus - D-Bus Bus Object.
 *  @param[in] service - D-Bus service name.
 *  @param[in] objPath - D-Bus object path.
 *  @return On success returns the map of name value pair.
 */
ObjectValueTree getManagedObjects(sdbusplus::bus::bus& bus,
                                  const std::string& service,
                                  const std::string& objPath);

/** @brief Sets the property value of the given object.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @param[in] value - value which needs to be set.
 */
void setDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                     const std::string& objPath, const std::string& interface,
                     const std::string& property, const Value& value,
                     std::chrono::microseconds timeout = IPMI_DBUS_TIMEOUT);

/** @brief  Gets all the dbus objects from the given service root
 *          which matches the object identifier.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] serviceRoot - Service root path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] match - Identifier for a path.
 *  @returns map of object path and service info.
 */
ObjectTree getAllDbusObjects(sdbusplus::bus::bus& bus,
                             const std::string& serviceRoot,
                             const std::string& interface,
                             const std::string& match = {});

/** @brief Deletes all the dbus objects from the given service root
           which matches the object identifier.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] serviceRoot - Service root path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] match - Identifier for object.
 */
void deleteAllDbusObjects(sdbusplus::bus::bus& bus,
                          const std::string& serviceRoot,
                          const std::string& interface,
                          const std::string& match = {});

/** @brief Gets the ancestor objects of the given object
           which implements the given interface.
 *  @param[in] bus - Dbus bus object.
 *  @param[in] path - Child Dbus object path.
 *  @param[in] interfaces - Dbus interface list.
 *  @return map of object path and service info.
 */
ObjectTree getAllAncestors(sdbusplus::bus::bus& bus, const std::string& path,
                           InterfaceList&& interfaces);

/** @struct VariantToDoubleVisitor
 *  @brief Visitor to convert variants to doubles
 *  @details Performs a static cast on the underlying type
 */
struct VariantToDoubleVisitor
{
    template <typename T>
    std::enable_if_t<std::is_arithmetic<T>::value, double>
        operator()(const T& t) const
    {
        return static_cast<double>(t);
    }

    template <typename T>
    std::enable_if_t<!std::is_arithmetic<T>::value, double>
        operator()(const T& t) const
    {
        throw std::invalid_argument("Cannot translate type to double");
    }
};

namespace method_no_args
{

/** @brief Calls the Dbus method which waits for response.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] method - Dbus method.
 */
void callDbusMethod(sdbusplus::bus::bus& bus, const std::string& service,
                    const std::string& objPath, const std::string& interface,
                    const std::string& method);

} // namespace method_no_args

/** @brief Perform the low-level i2c bus write-read.
 *  @param[in] i2cBus - i2c bus device node name, such as /dev/i2c-2.
 *  @param[in] slaveAddr - i2c device slave address.
 *  @param[in] writeData - The data written to i2c device.
 *  @param[out] readBuf - Data read from the i2c device.
 */
ipmi::Cc i2cWriteRead(std::string i2cBus, const uint8_t slaveAddr,
                      std::vector<uint8_t> writeData,
                      std::vector<uint8_t>& readBuf);
} // namespace ipmi
