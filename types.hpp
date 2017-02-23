#include <string>
#include <stdint.h>
#include <map>
#include <iostream>
#include <variant>

using IPMISensorMetadata = std::string;
using IPMISensorMetadataValue = std::variant<bool,uint8_t,std::string>;

using IPMISensorMap = std::map<IPMISensorMetadata,IPMISensorMetadataValue>;

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
