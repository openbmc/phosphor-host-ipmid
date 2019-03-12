#pragma once

#include <chrono>
#include <ipmid/types.hpp>
#include <optional>
#include <sdbusplus/server.hpp>

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

/** @brief Get the ipObject of first dbus IP object of Non-LinkLocalIPAddress
 *         type from the given subtree, if not available gets IP object of
 *         LinkLocalIPAddress type.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] interface - Dbus interface.
 *  @param[in] subtreePath - subtree from where the search should start.
 *  @param[in] match - identifier for object.
 *  @return On success returns the object having objectpath and servicename.
 */
DbusObjectInfo getIPObject(sdbusplus::bus::bus& bus,
                           const std::string& interface,
                           const std::string& subtreePath,
                           const std::string& match);

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

namespace network
{

constexpr auto ROOT = "/xyz/openbmc_project/network";
constexpr auto SERVICE = "xyz.openbmc_project.Network";
constexpr auto IP_TYPE = "ipv4";
constexpr auto IPV4_PREFIX = "169.254";
constexpr auto IPV6_PREFIX = "fe80";
constexpr auto IP_INTERFACE = "xyz.openbmc_project.Network.IP";
constexpr auto MAC_INTERFACE = "xyz.openbmc_project.Network.MACAddress";
constexpr auto SYSTEMCONFIG_INTERFACE =
    "xyz.openbmc_project.Network.SystemConfiguration";
constexpr auto ETHERNET_INTERFACE =
    "xyz.openbmc_project.Network.EthernetInterface";
constexpr auto IP_CREATE_INTERFACE = "xyz.openbmc_project.Network.IP.Create";
constexpr auto VLAN_CREATE_INTERFACE =
    "xyz.openbmc_project.Network.VLAN.Create";
constexpr auto VLAN_INTERFACE = "xyz.openbmc_project.Network.VLAN";

/* @brief converts the given subnet into prefix notation.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] mask - Subnet Mask.
 * @returns prefix.
 */
uint8_t toPrefix(int addressFamily, const std::string& subnetMask);

/** @brief Sets the ip on the system.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] protocolType - Protocol type
 *  @param[in] ipaddress - IPaddress.
 *  @param[in] prefix - Prefix length.
 */
void createIP(sdbusplus::bus::bus& bus, const std::string& service,
              const std::string& objPath, const std::string& protocolType,
              const std::string& ipaddress, uint8_t prefix);

/** @brief Creates the VLAN on the given interface.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - EthernetInterface.
 *  @param[in] vlanID - Vlan ID.
 */
void createVLAN(sdbusplus::bus::bus& bus, const std::string& service,
                const std::string& objPath, const std::string& interface,
                uint32_t vlanID);

/** @brief Gets the vlan id from the given object path.
 *  @param[in] path - Dbus object path.
 */
uint32_t getVLAN(const std::string& path);

} // namespace network
} // namespace ipmi
