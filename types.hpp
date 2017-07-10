#pragma once

#include <stdint.h>

#include <map>
#include <string>

#include <sdbusplus/server.hpp>

namespace ipmi
{

using DbusProperty = std::string;
using Value = sdbusplus::message::variant<bool, int64_t, uint8_t, std::string>;
using PropertyMap = std::map<DbusProperty, Value>;

namespace sensor
{

using Offset = uint8_t;
using Value = ipmi::Value;

struct Values
{
   Value assert;
   Value deassert;
};

using OffsetValueMap = std::map<Offset,Values>;

using DbusProperty = ipmi::DbusProperty;
using DbusPropertyMap = std::map<DbusProperty,OffsetValueMap>;

using DbusInterface = std::string;
using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using InstancePath = std::string;
using Type = uint8_t;
using ReadingType = uint8_t;

struct Info
{
   Type sensorType;
   InstancePath sensorPath;
   ReadingType sensorReadingType;
   DbusInterfaceMap sensorInterfaces;
};

using Id = uint8_t;
using IdInfoMap = std::map<Id,Info>;

using PropertyMap = ipmi::PropertyMap;

using InterfaceMap = std::map<DbusInterface, PropertyMap>;

using Object = sdbusplus::message::object_path;
using ObjectMap = std::map<Object, InterfaceMap>;

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
