#pragma once

#include <stdint.h>

#include <map>
#include <string>

#include <sdbusplus/server.hpp>

namespace ipmi
{

using DbusObjectPath = std::string;
using DbusService = std::string;
using DbusInterface = std::string;
using DbusObjectInfo = std::pair<DbusObjectPath, DbusService>;
using DbusProperty = std::string;

using Value = sdbusplus::message::variant<bool, uint8_t, int16_t,
                                          uint16_t, int32_t, uint32_t,
                                          int64_t, uint64_t, std::string>;

using PropertyMap = std::map<DbusProperty, Value>;

using ObjectTree = std::map<DbusObjectPath,
                            std::map<DbusService, std::vector<DbusInterface>>>;

using InterfaceList = std::vector<std::string>;

namespace sensor
{

using Offset = uint8_t;

/**
 * @enum SkipAssertion
 * Matching value for skipping the update
 */
enum class SkipAssertion
{
    NONE,
    ASSERT,
    DEASSERT,
};

struct Values
{
   SkipAssertion skip;
   Value assert;
   Value deassert;
};

/**
 * @struct SetSensorReadingReq
 *
 * IPMI Request data for Set Sensor Reading and Event Status Command
 */
struct SetSensorReadingReq
{
    uint8_t number;
    uint8_t operation;
    uint8_t reading;
    uint8_t assertOffset0_7;
    uint8_t assertOffset8_14;
    uint8_t deassertOffset0_7;
    uint8_t deassertOffset8_14;
    uint8_t eventData1;
    uint8_t eventData2;
    uint8_t eventData3;
} __attribute__((packed));

/**
 * @struct GetReadingResponse
 *
 * IPMI response data for Get Sensor Reading command.
 */
struct GetReadingResponse
{
    uint8_t reading;            //!< Sensor reading.
    uint8_t operation;          //!< Sensor scanning status / reading state.
    uint8_t assertOffset0_7;    //!< Discrete assertion states(0-7).
    uint8_t assertOffset8_14;   //!< Discrete assertion states(8-14).
} __attribute__((packed));

constexpr auto inventoryRoot = "/xyz/openbmc_project/inventory";

using GetSensorResponse = std::array<uint8_t, sizeof(GetReadingResponse)>;

using OffsetValueMap = std::map<Offset,Values>;

using DbusPropertyMap = std::map<DbusProperty,OffsetValueMap>;

using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using InstancePath = std::string;
using Type = uint8_t;
using ReadingType = uint8_t;
using Multiplier = uint16_t;
using OffsetB = uint16_t;
using Exponent = uint8_t;
using ScaledOffset = int64_t;

enum class Mutability
{
   Read = 1 << 0,
   Write = 1 << 1,
};

inline Mutability operator|(Mutability lhs, Mutability rhs)
{
  return static_cast<Mutability>(
      static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}

inline Mutability operator&(Mutability lhs, Mutability rhs)
{
  return static_cast<Mutability>(
      static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
}

struct Info
{
   Type sensorType;
   InstancePath sensorPath;
   DbusInterface sensorInterface;
   ReadingType sensorReadingType;
   Multiplier coefficientM;
   OffsetB coefficientB;
   Exponent exponentB;
   ScaledOffset scaledOffset;
   std::function<uint8_t(SetSensorReadingReq&, const Info&)> updateFunc;
   std::function<GetSensorResponse(const Info&)> getFunc;
   Mutability mutability;
   DbusInterfaceMap propertyInterfaces;
};

using Id = uint8_t;
using IdInfoMap = std::map<Id,Info>;

using PropertyMap = ipmi::PropertyMap;

using InterfaceMap = std::map<DbusInterface, PropertyMap>;

using Object = sdbusplus::message::object_path;
using ObjectMap = std::map<Object, InterfaceMap>;

using IpmiUpdateData = sdbusplus::message::message;

struct SelData
{
   Id sensorID;
   Type sensorType;
   ReadingType eventReadingType;
   Offset eventOffset;
};

using InventoryPath = std::string;

using InvObjectIDMap = std::map<InventoryPath, SelData>;

}// namespace sensor

namespace network
{

constexpr auto MAC_ADDRESS_FORMAT = "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx";
constexpr auto IP_ADDRESS_FORMAT = "%u.%u.%u.%u";
constexpr auto PREFIX_FORMAT = "%hhd";
constexpr auto ADDR_TYPE_FORMAT = "%hhx";

constexpr auto IPV4_ADDRESS_SIZE_BYTE = 4;
constexpr auto IPV6_ADDRESS_SIZE_BYTE = 16;

constexpr auto DEFAULT_MAC_ADDRESS = "00:00:00:00:00:00";
constexpr auto DEFAULT_ADDRESS = "0.0.0.0";

constexpr auto MAC_ADDRESS_SIZE_BYTE = 6;
constexpr auto VLAN_SIZE_BYTE = 2;
constexpr auto IPSRC_SIZE_BYTE = 1;
constexpr auto BITS_32 = 32;
constexpr auto MASK_32_BIT = 0xFFFFFFFF;
constexpr auto VLAN_ID_MASK = 0x00000FFF;
constexpr auto VLAN_ENABLE_MASK = 0x8000;

enum class IPOrigin: uint8_t
{
    UNSPECIFIED = 0,
    STATIC = 1,
    DHCP = 2,
};


}//namespace network
}//namespace ipmi
