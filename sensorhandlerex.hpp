#ifndef __HOST_IPMI_SEN_HANDLEREX_HPP__
#define __HOST_IPMI_SEN_HANDLEREX_HPP__

#include "types.hpp"
#include "sensorhandler.h"

namespace ipmi
{
namespace sensor
{

uint8_t getValue(uint8_t offset,SetSensorReadingReq *cmd);

uint8_t setInventorySensorReading(SetSensorReadingReq *cmdData,
                                     Info &sensorInfo);

uint8_t setPropertySensorReading(SetSensorReadingReq *cmdData,
                                    Info &sensorInfo);
}
}
#endif
