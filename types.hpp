#pragma once

#include <stdint.h>

#include <map>
#include <string>

#include <sdbusplus/server.hpp>

namespace ipmi
{
namespace sensor
{

using Offset = uint8_t;
using Value = sdbusplus::message::variant<bool, int64_t, std::string>;
// Sensor.Value.Value -> x
using Reading = sdbusplus::message::variant<int64_t>;

struct Values
{
   Value assert;
   Value deassert;
};

using OffsetValueMap = std::map<Offset,Values>;

using DbusProperty = std::string;
using DbusPropertyMap = std::map<DbusProperty,OffsetValueMap>;

using DbusInterface = std::string;
using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using InstancePath = std::string;
using Type = uint8_t;
using ReadingType = uint8_t;
using Multiplier = uint16_t;
using OffsetB = uint16_t;
using Exponent = uint8_t;
using ScaledOffset = int64_t;

enum Mutability {
   Read = 1 << 0,
   Write = 1 << 1,
};

struct Info
{
   Type sensorType;
   InstancePath sensorPath;
   ReadingType sensorReadingType;
   Multiplier coefficientM;
   OffsetB coefficientB;
   Exponent exponentB;
   ScaledOffset scaledOffset;
   Mutability mutability;
   DbusInterfaceMap sensorInterfaces;
};

using Id = uint8_t;
using IdInfoMap = std::map<Id,Info>;

using ValuePropertyMap = std::map<DbusProperty, Value>;
using ValueInterfaceMap = std::map<DbusInterface, ValuePropertyMap>;

using ReadingPropertyMap = std::map<DbusProperty, Reading>;
using ReadingInterfaceMap = std::map<DbusInterface, ReadingPropertyMap>;

using Object = sdbusplus::message::object_path;
using ValueObjectMap = std::map<Object, ValueInterfaceMap>;
using ReadingObjectMap = std::map<Object, ReadingInterfaceMap>;

struct SelData
{
   Id sensorID;
   Type sensorType;
   ReadingType eventReadingType;
   Offset eventOffset;
};

using InventoryPath = std::string;

using InvObjectIDMap = std::map<InventoryPath, SelData>;

}//namespce sensor
}//namespace ipmi
