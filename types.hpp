#include <string>
#include <stdint.h>
#include <map>
#include <iostream>
using IPMISensorMetadata = std::string;
using IPMISensorMetadataValue = std::string;
using IPMISensorMap = std::map<IPMISensorMetadata,IPMISensorMetadataValue>;

using DbusProperty = std::string;
using DbusPropertyMap = std::map<DbusProperty,IPMISensorMap>;

using DbusInterface = std::string;
using DbusInterfaceMap = std::map<DbusInterface,DbusPropertyMap>;

using sensorInstancePath = std::string;

typedef struct sensorInfo
{
   uint8_t sensorType;
   sensorInstancePath sensorPath;
   uint8_t sensrorReadingType;
   DbusInterfaceMap sensorInterfaces;
}sensorInfo;


using sensorId = uint32_t;
using sensorMap = std::map<sensorId,sensorInfo>;
