#include <string>
#include <stdint.h>
#include <map>
#include <iostream>
#include <sdbusplus/server.hpp>

using IPMISensorOffset = uint8_t;
using IPMISensorOffsetValue = sdbusplus::message::variant<bool, int64_t, std::string>;

struct SensorValue
{
   IPMISensorOffsetValue assert;
   IPMISensorOffsetValue deassert;
};

using IPMISensorMap = std::map<IPMISensorOffset,SensorValue>;

using DbusProperty = std::string;
using DbusPropertyMap = std::map<DbusProperty,IPMISensorMap>;

using DbusInterface = std::string;
using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using SensorInstancePath = std::string;
using SensorType = uint8_t;
using SensorReadingType = uint8_t;

struct SensorInfo
{
   SensorType sensorType;
   SensorInstancePath sensorPath;
   SensorReadingType sensorReadingType;
   DbusInterfaceMap sensorInterfaces;
};


using sensorId = uint8_t;
using sensorMap = std::map<sensorId,SensorInfo>;
