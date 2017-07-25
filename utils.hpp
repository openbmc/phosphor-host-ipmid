#pragma once

#include "types.hpp"
#include <sdbusplus/server.hpp>

namespace ipmi
{

constexpr auto MAPPER_BUS_NAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_OBJ = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTF = "xyz.openbmc_project.ObjectMapper";

constexpr auto ROOT = "/";
constexpr auto HOST_MATCH = "host0";
constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";

constexpr auto IP_INTERFACE = "xyz.openbmc_project.Network.IP";
constexpr auto MAC_INTERFACE = "xyz.openbmc_project.Network.MACAddress";

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
 *  @param[in] subtreePath - subtree from where the search should start.
 *  @param[in] match - identifier for object.
 *  @return On success returns the object having objectpath and servicename.
 */
DbusObjectInfo getDbusObject(const std::string& interface,
                                   const std::string& subtreePath = ROOT,
                                   const std::string& match = {});

/** @brief Gets the value associated with the given object
 *         and the interface.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @return On success returns the value of the property.
 */
Value getDbusProperty(const std::string& service,
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
PropertyMap getAllDbusProperties(const std::string& service,
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
                     const Value& value);

} // namespace ipmi


