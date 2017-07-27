#pragma once

#include "types.hpp"
#include <sdbusplus/server.hpp>

namespace ipmi
{

constexpr auto MAPPER_BUS_NAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_OBJ = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTF = "xyz.openbmc_project.ObjectMapper";

constexpr auto SETTINGS_ROOT = "/";
constexpr auto NETWORK_ROOT = "/xyz/openbmc_project/network";
constexpr auto NETWORK_SERVICE = "xyz.openbmc_project.Network";
constexpr auto SETTINGS_MATCH = "host0";
constexpr auto INTERFACE = "eth0";
constexpr auto IP_TYPE = "ipv4";

constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";

constexpr auto IP_INTERFACE = "xyz.openbmc_project.Network.IP";
constexpr auto MAC_INTERFACE = "xyz.openbmc_project.Network.MACAddress";
constexpr auto SYSTEMCONFIG_INTERFACE = "xyz.openbmc_project.Network.SystemConfiguration";
constexpr auto DELETE_INTERFACE = "xyz.openbmc_project.Object.Delete";
constexpr auto ETHERNET_INTERFACE = "xyz.openbmc_project.Network.EthernetInterface";

constexpr auto IP_CREATE_INTERFACE = "xyz.openbmc_project.Network.IP.Create";
constexpr auto METHOD_GET = "Get";
constexpr auto METHOD_GET_ALL = "GetAll";
constexpr auto METHOD_SET = "Set";


/**
 * @brief Get the DBUS Service name for the input dbus path
 *
 * @param[in] bus - DBUS Bus Object
 * @param[in] intf - DBUS Interface
 * @param[in] path - DBUS Object Path
 *
 */
std::string getService(sdbusplus::bus::bus& bus,
                       const std::string& intf,
                       const std::string& path);
/** @brief Gets the dbus object info implementing the given interface
 *         from the given subtree.
 *  @param[in] interface - Dbus interface.
 *  @param[in] serviceRoot - subtree from where the search should start.
 *  @param[in] match - identifier for object.
 *  @return On success returns the object having objectpath and servicename.
 */
ipmi::DbusObjectInfo getDbusObject(const std::string& interface,
                                   const std::string& serviceRoot = SETTINGS_ROOT,
                                   const std::string& match = "");

/** @brief Gets the value associated with the given object
 *         and the interface.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @return On success returns the value of the property.
 */
std::string getDbusProperty(const std::string& service,
                            const std::string& objPath,
                            const std::string& interface,
                            const std::string& property);

/** @brief Gets all the properties associated with the given object
 *         and the interface.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @return On success returns the map of name value pair.
 */
ipmi::PropertyMap getAllDbusProperties(const std::string& service,
                                       const std::string& objPath,
                                       const std::string& interface);
/** @brief Sets the property value of the given object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @param[in] value - value which needs to be set.
 */
void setDbusProperty(const std::string& service,
                     const std::string& objPath,
                     const std::string& interface,
                     const std::string& property,
                     const ipmi::Value& value);

/* @brief converts the given subnet into prefix notation.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] mask - Subnet Mask.
 * @returns prefix.
 */
uint8_t toCidr(int addressFamily, const std::string& subnetMask);

/** @brief Calls the Dbus method.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] method - Dbus method.
 *  @param[in] dataList - Method data.//TODO
 */
void callDbusMethod(const std::string& service,
                    const std::string& objPath,
                    const std::string& interface,
                    const std::string& method,
                    ipmi::DbusDataVector& dataList);

/** @brief Sets the ip on the system.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] ipaddress - IPaddress.
 *  @param[in] prefix - Prefix length.
 */
void createIP(const std::string& service,
              const std::string& objPath,
              const std::string& ipaddress,
              uint8_t prefix);


/** @brief  Gets all the dbus objects from the given service root
 *          which matches the object identifier.
 *  @param[in] serviceRoot - Service root path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] match - Identifier for object.
 *  @returns map of object path and service info.
 */
ipmi::ObjectTree  getAllDbusObject(const std::string& serviceRoot,
                                   const std::string& interface,
                                   const std::string& match);

/** @brief Deletes all the dbus objects from the given service root
           which matches the object identifier.
 *  @param[in] serviceRoot - Service root path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] match - Identifier for object.
 */
void deleteAllDbusObject(const std::string& serviceRoot,
                         const std::string& interface,
                         const std::string& match = "");

} // namespace ipmi


