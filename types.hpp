#pragma once

#include <stdint.h>

#include <map>
#include <string>

#include <sdbusplus/server.hpp>
#include "sensorhandler.h"

namespace ipmi
{

using DbusObjectPath = std::string;
using DbusService = std::string;
using DbusInterface = std::string;
using DbusObjectInfo = std::pair<DbusObjectPath, DbusService>;
using DbusProperty = std::string;
using Value = sdbusplus::message::variant<bool, int64_t, uint8_t, std::string>;
using PropertyMap = std::map<DbusProperty, Value>;
using ObjectTree = std::map<DbusObjectPath,
                            std::map<DbusService, std::vector<DbusInterface>>>;
namespace sensor
{

/**
 * @enum ValueReadingType
 *
 * IPMI data types in request
 */
enum ValueReadingType{
   IPMI_TYPE_ASSERTION,
   IPMI_TYPE_READING,
   IPMI_TYPE_EVENT1,
   IPMI_TYPE_EVENT2,
   IPMI_TYPE_EVENT3,
};

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

using DbusInterface = ipmi::DbusInterface;
using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using InstancePath = std::string;
using Type = uint8_t;
using ReadingType = uint8_t;
using Multiplier = uint16_t;
using OffsetB = uint16_t;
using Exponent = uint8_t;
using ScaledOffset = int64_t;

using UpdateInterface = std::string;

struct Info
{
   Type sensorType;
   InstancePath sensorPath;
   ReadingType sensorReadingType;
   Multiplier coefficientM;
   OffsetB coefficientB;
   Exponent exponentB;
   ScaledOffset scaledOffset;
   ValueReadingType valueReadingType;
   std::function<uint8_t(SetSensorReadingReq*,Info)> updateFunc;
   std::function<uint8_t(SetSensorReadingReq*)> getSensorValue;
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
