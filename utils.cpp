#include "utils.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

namespace ipmi
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

/** @brief Gets the dbus object info implementing the given interface
 *         from the given subtree.
 *  @param[in] interface - Dbus interface.
 *  @param[in] serviceRoot - subtree from where the search should start.
 *  @param[in] match - identifier for object.
 *  @return On success returns the object having objectpath and servicename.
 */

//TODO There may be cases where an interface is implemented by multiple
//  objects,to handle such cases we are interested on that object
//  which are on interested busname.
//  Currently mapper doesn't give the readable busname(gives busid) so we can't
//  use busname to find the object,will do later once the support is there.

inline DbusObjectInfo getDbusObject(const std::string& interface,
                                    const std::string& serviceRoot,
                                    const std::string& match)
{
    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(interface);

    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    auto depth = 0;

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME,
                                          MAPPER_OBJ,
                                          MAPPER_INTF,
                                          "GetSubTree");

    mapperCall.append(serviceRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has impelmented the interface",
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    DbusObjectInfo objectInfo;

    // if match is empty then return the first object
    if(match == "")
    {
        objectInfo =  std::make_pair(objectTree.begin()->first,
            std::move(objectTree.begin()->second.begin()->first));
        return objectInfo;
    }

    // else search the match string in the object path
    auto objectFound = false;
    for (auto& object : objectTree)
    {
        if(object.first.find(match) != std::string::npos)
        {
            objectFound = true;
            objectInfo = make_pair(object.first,
                            std::move(object.second.begin()->first));
            break;
        }
    }

    if(!objectFound)
    {
        log<level::ERR>("Failed to find object which matches",
                        entry("MATCH=%s", match.c_str()));
        elog<InternalFailure>();
    }
    return objectInfo;

}

/** @brief Gets the value associated with the given object
 *         and the interface.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @return On success returns the value of the property.
 */
inline Value getDbusProperty(const std::string& service,
                             const std::string& objPath,
                             const std::string& interface,
                             const std::string& property)
{

    Value value;

    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    auto method = bus.new_method_call(
                      service.c_str(),
                      objPath.c_str(),
                      PROP_INTF,
                      METHOD_GET);

    method.append(interface, property);

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
         log<level::ERR>("Failed to get property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    reply.read(value);

    return value;
}

/** @brief Gets all the properties associated with the given object
 *         and the interface.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @return On success returns the map of name value pair.
 */
inline PropertyMap getAllDbusProperties(const std::string& service,
                                        const std::string& objPath,
                                        const std::string& interface)
{
    PropertyMap properties;

    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
    auto method = bus.new_method_call(
                      service.c_str(),
                      objPath.c_str(),
                      PROP_INTF,
                      METHOD_GET_ALL);

    method.append(interface);

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
         log<level::ERR>("Failed to get all properties",
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
         elog<InternalFailure>();
    }

    reply.read(properties);
    return properties;
}

/** @brief Sets the property value of the given object.
 *  @param[in] service - Dbus service name.
 *  @param[in] objPath - Dbus object path.
 *  @param[in] interface - Dbus interface.
 *  @param[in] property - name of the property.
 *  @param[in] value - value which needs to be set.
 */
inline void setDbusProperty(const std::string& service,
                            const std::string& objPath,
                            const std::string& interface,
                            const std::string& property,
                            const Value& value)
{
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    auto method = bus.new_method_call(
                      service.c_str(),
                      objPath.c_str(),
                      PROP_INTF,
                      METHOD_SET);

    method.append(interface, property, value);

    if (!bus.call(method))
    {
        log<level::ERR>("Failed to set property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s",objPath.c_str()),
                        entry("INTERFACE=%s",interface.c_str()));
        elog<InternalFailure>();
    }

}


std::string getService(sdbusplus::bus::bus& bus,
                       const std::string& intf,
                       const std::string& path)
{
    auto mapperCall = bus.new_method_call("xyz.openbmc_project.ObjectMapper",
                                          "/xyz/openbmc_project/object_mapper",
                                          "xyz.openbmc_project.ObjectMapper",
                                          "GetObject");

    mapperCall.append(path);
    mapperCall.append(std::vector<std::string>({intf}));

    auto mapperResponseMsg = bus.call(mapperCall);

    if (mapperResponseMsg.is_method_error())
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw std::runtime_error("ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}


} // namespace ipmi


