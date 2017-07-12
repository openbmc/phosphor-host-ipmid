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
using Value = sdbusplus::message::variant<bool, int64_t, uint8_t, std::string>;

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

using UpdateInterface = std::string;
using UpdatePath = std::string;
using UpdateCommand = std::string;
using ValueReadingType = std::string;
using ByteOffset = uint8_t;

struct Info
{
   Type sensorType;
   InstancePath sensorPath;
   ReadingType sensorReadingType;
   UpdatePath  updatePath;
   UpdateInterface updateInterface;
   UpdateCommand updateCommand;
   ValueReadingType valueReadingType;
   ByteOffset byteOffset;
   DbusInterfaceMap sensorInterfaces;
};

using Id = uint8_t;
using IdInfoMap = std::map<Id,Info>;

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
