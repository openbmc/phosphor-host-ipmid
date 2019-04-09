#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

#include <algorithm>
#include <chrono>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace ipmi
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace network
{

/** @brief checks if the given ip is Link Local Ip or not.
 *  @param[in] ipaddress - IPAddress.
 */
bool isLinkLocalIP(const std::string& ipaddress);

} // namespace network

// TODO There may be cases where an interface is implemented by multiple
//  objects,to handle such cases we are interested on that object
//  which are on interested busname.
//  Currently mapper doesn't give the readable busname(gives busid) so we can't
//  use busname to find the object,will do later once the support is there.

DbusObjectInfo getDbusObject(sdbusplus::bus::bus& bus,
                             const std::string& interface,
                             const std::string& serviceRoot,
                             const std::string& match)
{
    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(interface);

    auto depth = 0;

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ,
                                          MAPPER_INTF, "GetSubTree");

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
        log<level::ERR>("No Object has implemented the interface",
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    DbusObjectInfo objectInfo;

    // if match is empty then return the first object
    if (match == "")
    {
        objectInfo = std::make_pair(
            objectTree.begin()->first,
            std::move(objectTree.begin()->second.begin()->first));
        return objectInfo;
    }

    // else search the match string in the object path
    auto found = std::find_if(
        objectTree.begin(), objectTree.end(), [&match](const auto& object) {
            return (object.first.find(match) != std::string::npos);
        });

    if (found == objectTree.end())
    {
        log<level::ERR>("Failed to find object which matches",
                        entry("MATCH=%s", match.c_str()));
        elog<InternalFailure>();
        // elog<> throws an exception.
    }

    return make_pair(found->first, std::move(found->second.begin()->first));
}

DbusObjectInfo getIPObject(sdbusplus::bus::bus& bus,
                           const std::string& interface,
                           const std::string& serviceRoot,
                           const std::string& match)
{
    auto objectTree = getAllDbusObjects(bus, serviceRoot, interface, match);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the IP interface",
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    DbusObjectInfo objectInfo;

    for (auto& object : objectTree)
    {
        auto variant = ipmi::getDbusProperty(
            bus, object.second.begin()->first, object.first,
            ipmi::network::IP_INTERFACE, "Address");

        objectInfo = std::make_pair(object.first, object.second.begin()->first);

        // if LinkLocalIP found look for Non-LinkLocalIP
        if (ipmi::network::isLinkLocalIP(std::get<std::string>(variant)))
        {
            continue;
        }
        else
        {
            break;
        }
    }
    return objectInfo;
}

Value getDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                      const std::string& objPath, const std::string& interface,
                      const std::string& property,
                      std::chrono::microseconds timeout)
{

    Value value;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_GET);

    method.append(interface, property);

    auto reply = bus.call(method, timeout.count());

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

PropertyMap getAllDbusProperties(sdbusplus::bus::bus& bus,
                                 const std::string& service,
                                 const std::string& objPath,
                                 const std::string& interface,
                                 std::chrono::microseconds timeout)
{
    PropertyMap properties;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_GET_ALL);

    method.append(interface);

    auto reply = bus.call(method, timeout.count());

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

ObjectValueTree getManagedObjects(sdbusplus::bus::bus& bus,
                                  const std::string& service,
                                  const std::string& objPath)
{
    ipmi::ObjectValueTree interfaces;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to get managed objects",
                        entry("PATH=%s", objPath.c_str()));
        elog<InternalFailure>();
    }

    reply.read(interfaces);
    return interfaces;
}

void setDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                     const std::string& objPath, const std::string& interface,
                     const std::string& property, const Value& value,
                     std::chrono::microseconds timeout)
{
    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_SET);

    method.append(interface, property, value);

    if (!bus.call(method, timeout.count()))
    {
        log<level::ERR>("Failed to set property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }
}

ServiceCache::ServiceCache(const std::string& intf, const std::string& path) :
    intf(intf), path(path), cachedService(std::nullopt),
    cachedBusName(std::nullopt)
{
}

ServiceCache::ServiceCache(std::string&& intf, std::string&& path) :
    intf(std::move(intf)), path(std::move(path)), cachedService(std::nullopt),
    cachedBusName(std::nullopt)
{
}

const std::string& ServiceCache::getService(sdbusplus::bus::bus& bus)
{
    if (!isValid(bus))
    {
        cachedBusName = bus.get_unique_name();
        cachedService = ::ipmi::getService(bus, intf, path);
    }
    return cachedService.value();
}

void ServiceCache::invalidate()
{
    cachedBusName = std::nullopt;
    cachedService = std::nullopt;
}

sdbusplus::message::message
    ServiceCache::newMethodCall(sdbusplus::bus::bus& bus, const char* intf,
                                const char* method)
{
    return bus.new_method_call(getService(bus).c_str(), path.c_str(), intf,
                               method);
}

bool ServiceCache::isValid(sdbusplus::bus::bus& bus) const
{
    return cachedService && cachedBusName == bus.get_unique_name();
}

std::string getService(sdbusplus::bus::bus& bus, const std::string& intf,
                       const std::string& path)
{
    auto mapperCall =
        bus.new_method_call("xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper", "GetObject");

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

ipmi::ObjectTree getAllDbusObjects(sdbusplus::bus::bus& bus,
                                   const std::string& serviceRoot,
                                   const std::string& interface,
                                   const std::string& match)
{
    std::vector<std::string> interfaces;
    interfaces.emplace_back(interface);

    auto depth = 0;

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ,
                                          MAPPER_INTF, "GetSubTree");

    mapperCall.append(serviceRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call",
                        entry("SERVICEROOT=%s", serviceRoot.c_str()),
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

void deleteAllDbusObjects(sdbusplus::bus::bus& bus,
                          const std::string& serviceRoot,
                          const std::string& interface,
                          const std::string& match)
{
    try
    {
        auto objectTree = getAllDbusObjects(bus, serviceRoot, interface, match);

        for (auto& object : objectTree)
        {
            method_no_args::callDbusMethod(bus, object.second.begin()->first,
                                           object.first, DELETE_INTERFACE,
                                           "Delete");
        }
    }
    catch (sdbusplus::exception::exception& e)
    {
        log<level::INFO>("sdbusplus exception - Unable to delete the objects",
                         entry("ERROR=%s", e.what()),
                         entry("INTERFACE=%s", interface.c_str()),
                         entry("SERVICE=%s", serviceRoot.c_str()));
    }
}

ObjectTree getAllAncestors(sdbusplus::bus::bus& bus, const std::string& path,
                           InterfaceList&& interfaces)
{
    auto convertToString = [](InterfaceList& interfaces) -> std::string {
        std::string intfStr;
        for (const auto& intf : interfaces)
        {
            intfStr += "," + intf;
        }
        return intfStr;
    };

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ,
                                          MAPPER_INTF, "GetAncestors");
    mapperCall.append(path, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>(
            "Error in mapper call", entry("PATH=%s", path.c_str()),
            entry("INTERFACES=%s", convertToString(interfaces).c_str()));

        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        log<level::ERR>(
            "No Object has implemented the interface",
            entry("PATH=%s", path.c_str()),
            entry("INTERFACES=%s", convertToString(interfaces).c_str()));
        elog<InternalFailure>();
    }

    return objectTree;
}

namespace method_no_args
{

void callDbusMethod(sdbusplus::bus::bus& bus, const std::string& service,
                    const std::string& objPath, const std::string& interface,
                    const std::string& method)

{
    auto busMethod = bus.new_method_call(service.c_str(), objPath.c_str(),
                                         interface.c_str(), method.c_str());

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

} // namespace method_no_args

namespace network
{

bool isLinkLocalIP(const std::string& address)
{
    return address.find(IPV4_PREFIX) == 0 || address.find(IPV6_PREFIX) == 0;
}

void createIP(sdbusplus::bus::bus& bus, const std::string& service,
              const std::string& objPath, const std::string& protocolType,
              const std::string& ipaddress, uint8_t prefix)
{
    std::string gateway = "";

    auto busMethod = bus.new_method_call(service.c_str(), objPath.c_str(),
                                         IP_CREATE_INTERFACE, "IP");

    busMethod.append(protocolType, ipaddress, prefix, gateway);

    auto reply = bus.call(busMethod);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to execute method", entry("METHOD=%s", "IP"),
                        entry("PATH=%s", objPath.c_str()));
        elog<InternalFailure>();
    }
}

void createVLAN(sdbusplus::bus::bus& bus, const std::string& service,
                const std::string& objPath, const std::string& interfaceName,
                uint32_t vlanID)
{
    auto busMethod = bus.new_method_call(service.c_str(), objPath.c_str(),
                                         VLAN_CREATE_INTERFACE, "VLAN");

    busMethod.append(interfaceName, vlanID);

    auto reply = bus.call(busMethod);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to execute method", entry("METHOD=%s", "VLAN"),
                        entry("PATH=%s", objPath.c_str()));
        elog<InternalFailure>();
    }
}

uint8_t toPrefix(int addressFamily, const std::string& subnetMask)
{
    if (addressFamily == AF_INET6)
    {
        return 0;
    }

    uint32_t buff{};

    auto rc = inet_pton(addressFamily, subnetMask.c_str(), &buff);
    if (rc <= 0)
    {
        log<level::ERR>("inet_pton failed:",
                        entry("SUBNETMASK=%s", subnetMask.c_str()));
        return 0;
    }

    buff = be32toh(buff);
    // total no of bits - total no of leading zero == total no of ones
    if (((sizeof(buff) * 8) - (__builtin_ctz(buff))) ==
        __builtin_popcount(buff))
    {
        return __builtin_popcount(buff);
    }
    else
    {
        log<level::ERR>("Invalid Mask",
                        entry("SUBNETMASK=%s", subnetMask.c_str()));
        return 0;
    }
}

uint32_t getVLAN(const std::string& path)
{
    // Path would be look like
    // /xyz/openbmc_project/network/eth0_443/ipv4

    uint32_t vlanID = 0;
    try
    {
        auto intfObjectPath = path.substr(0, path.find(IP_TYPE) - 1);

        auto intfName = intfObjectPath.substr(intfObjectPath.rfind("/") + 1);

        auto index = intfName.find("_");
        if (index != std::string::npos)
        {
            auto str = intfName.substr(index + 1);
            vlanID = std::stoul(str);
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Exception occurred during getVLAN",
                        entry("PATH=%s", path.c_str()),
                        entry("EXCEPTION=%s", e.what()));
    }
    return vlanID;
}

} // namespace network
} // namespace ipmi
