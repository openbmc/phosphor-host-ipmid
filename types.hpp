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
using Value = sdbusplus::message::variant<bool, uint8_t, int64_t, std::string>;

struct Values
{
   Value assert;
   Value deassert;
};

using OffsetValueMap = std::map<Offset,Values>;

using ByteOffset = uint8_t;
using ByteOffsetValueMap = std::map<ByteOffset,OffsetValueMap>;

using EventType = std::string;
using EventTypeValueMap = std::map<EventType,ByteOffsetValueMap>;

using DbusProperty = std::string;
using DbusPropertyMap = std::map<DbusProperty,EventTypeValueMap>;


using DbusInterface = std::string;
using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using InstancePath = std::string;
using Type = uint8_t;
using ReadingType = uint8_t;

using UpdateInterface = std::string;
using UpdatePath = std::string;
using Command = std::string;

struct Info
{
   Type sensorType;
   InstancePath sensorPath;
   ReadingType sensorReadingType;
   UpdatePath  updatePath;
   UpdateInterface updateInterface;
   Command command;
   DbusInterfaceMap sensorInterfaces;
};

struct Info1
{
   Type sensorType;
   InstancePath sensorPath;
   ReadingType sensorReadingType;
   UpdatePath  updatePath;
   UpdateInterface updateInterface;
   Command command;
   OffsetValueMap sensorInterfaces;
};

using Id = uint8_t;
using IdInfoMap = std::map<Id,Info>;
using IdInfoMap1 = std::map<Id,Info1>;

using PropertyMap = std::map<DbusProperty, Value>;

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
