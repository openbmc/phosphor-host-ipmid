#include "utils.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

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

    auto bus = sdbusplus::bus::new_default();
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

    auto bus = sdbusplus::bus::new_default();

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
    auto bus = sdbusplus::bus::new_default();

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
    auto bus = sdbusplus::bus::new_default();

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

inline ipmi::ObjectTree  getAllDbusObject(const std::string& serviceRoot,
                                          const std::string& interface,
                                          const std::string& match)
{
    std::vector<std::string> interfaces;
    interfaces.emplace_back(interface);

    auto bus = sdbusplus::bus::new_default();
    auto depth = 0;

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME,
                                          MAPPER_OBJ,
                                          MAPPER_INTF,
                                          "GetSubTree");

    mapperCall.append(serviceRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call",
                        entry("SERVICEROOT=%s",serviceRoot.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));

        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    for (auto it = objectTree.begin(); it != objectTree.end();)
    {
        if (it->first.find(match) == std::string::npos)
        {
            it = objectTree.erase(it);
        }
        else
        {
            ++it;
        }
    }

    return objectTree;
}

inline void deleteAllDbusObjects(const std::string& serviceRoot,
                                 const std::string& interface,
                                 const std::string& match)
{
    try
    {
        DbusDataVector dataList;
        auto objectTree =  getAllDbusObject(serviceRoot, interface, match);
        for (auto& object : objectTree)
        {
            callDbusMethod(object.second.begin()->first, object.first,
                           DELETE_INTERFACE, "Delete", dataList);
        }
    }
    catch (InternalFailure& e)
    {
        log<level::INFO>("Unable to delete the objects having",
                         entry("INTERFACE=%s", interface.c_str()),
                         entry("SERVICE=%s", serviceRoot.c_str()));
    }
}

inline void callDbusMethod(const std::string& service,
                           const std::string& objPath,
                           const std::string& interface,
                           const std::string& method,
                           DbusDataVector& dataList)

{
    auto bus = sdbusplus::bus::new_default();


    auto busMethod = bus.new_method_call(
                         service.c_str(),
                         objPath.c_str(),
                         interface.c_str(),
                         method.c_str());

    for (auto& data : dataList)
    {
        busMethod.append(data);
    }

    auto reply = bus.call(busMethod);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to execute method",
                        entry("METHOD=%s", method.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

}

inline void createIP(const std::string& service,
                     const std::string& objPath,
                     const std::string& protocolType,
                     const std::string& ipaddress,
                     uint8_t prefix)
{
    std::string gateway = "";

    auto bus = sdbusplus::bus::new_default();

    auto busMethod = bus.new_method_call(
                         service.c_str(),
                         objPath.c_str(),
                         IP_CREATE_INTERFACE,
                         "IP");

    busMethod.append(protocolType, ipaddress, prefix, gateway);

    auto reply = bus.call(busMethod);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to excute method",
                        entry("METHOD=%s", "IP"),
                        entry("PATH=%s", objPath.c_str()));
        elog<InternalFailure>();
    }

}

inline void createVLAN(const std::string& service,
                       const std::string& objPath,
                       const std::string& interfaceName,
                       uint16_t vlanID)
{
    auto bus = sdbusplus::bus::new_default();


    auto busMethod = bus.new_method_call(
                         service.c_str(),
                         objPath.c_str(),
                         ipmi::VLAN_CREATE_INTERFACE,
                         "VLAN");

    busMethod.append(interfaceName, vlanID);

    auto reply = bus.call(busMethod);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to excute method",
                        entry("METHOD=%s", "VLAN"),
                        entry("PATH=%s", objPath.c_str()));
        elog<InternalFailure>();
    }

}

inline uint8_t toPrefix(int addressFamily, const std::string& subnetMask)
{
    if (addressFamily == AF_INET6)
    {
        return 0;
    }

    uint32_t buff;

    auto rc = inet_pton(addressFamily, subnetMask.c_str(), &buff);
    if (rc <= 0)
    {
        log<level::ERR>("inet_pton failed:",
                        entry("SUBNETMASK=%s", subnetMask));
        return 0;
    }

    buff = be32toh(buff);
    // total no of bits - total no of leading zero == total no of ones
    if (((sizeof(buff) * 8) - (__builtin_ctz(buff))) == __builtin_popcount(buff))
    {
        return __builtin_popcount(buff);
    }
    else
    {
        log<level::ERR>("Invalid Mask",
                        entry("SUBNETMASK=%s", subnetMask));
        return 0;
    }
}

inline uint32_t getVLAN(const std::string& path)
{
    // Path would be look like
    // /xyz/openbmc_project/network/eth0_443/ipv4

    uint32_t vlanID = 0;
    try
    {
        auto intfObjectPath = path.substr(0,
                path.find(ipmi::IP_TYPE) - 1);

        auto intfName = intfObjectPath.substr(intfObjectPath.rfind("/") + 1);

        auto index = intfName.find("_");
        if (index != std::string::npos)
        {
            auto str = intfName.substr(index + 1);
            vlanID = std::stoul(str, nullptr, 10);
            vlanID = atoi(str.c_str());
        }
    }
    catch (std::exception & e)
    {
        log<level::ERR>("Exception occured during getVLAN",
                        entry("PATH=%s",path.c_str()),
                        entry("EXCEPTIOn=%s", e.what()));
    }
    return vlanID;
}

} // namespace ipmi


