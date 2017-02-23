#include <stdint.h>
#include <map>
#include <iostream>
#include <sdbusplus/server.hpp>

namespace ipmi
{
namespace sensor
{

using Offset = uint8_t;
using ValueOnOffset = sdbusplus::message::variant<bool, int64_t, std::string>;

struct Value
{
   ValueOnOffset assert;
   ValueOnOffset deassert;
};

using OffsetValueMap = std::map<Offset,Value>;

using DbusProperty = std::string;
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


using ID = uint8_t;
using IDInfoMap = std::map<ID,Info>;

}//namespce sensor
}//namespace ipmi
