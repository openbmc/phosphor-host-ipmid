
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
#include <bitset>
#include "types.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/log.hpp>
#include "sensorhandler.h"

using namespace ipmi::sensor;
using namespace phosphor::logging;

constexpr auto MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;
using DbusInfo = std::pair<std::string, std::string>;

DbusInfo getDbusInfo(sdbusplus::bus::bus& bus, std::string interface)
{
    auto depth = 0;
    auto mapperCall = bus.new_method_call(MAPPER_BUSNAME,
                                          MAPPER_PATH,
                                          MAPPER_INTERFACE,
                                          "GetSubTree");
    mapperCall.append("/");
    mapperCall.append(depth);
    mapperCall.append(std::vector<std::string>({interface}));


    auto mapperResponseMsg = bus.call(mapperCall);
    if (mapperResponseMsg.is_method_error())
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    using MapperResponseType = std::map<std::string,
                               std::map<std::string, std::vector<std::string>>>;
    MapperResponseType mapperResponse;
    mapperResponseMsg.read(mapperResponse);
    if (mapperResponse.empty())
    {
        throw std::runtime_error("Invalid response from mapper");
    }

    return std::make_pair(mapperResponse.begin()->first,
        mapperResponse.begin()->second.begin()->first);
}

uint8_t getValue(ValueReadingType readingType, SetSensorReadingReq *cmd)
{
    if (readingType == IPMI_TYPE_ASSERTION)
    {
        return 0;
    }
    if(readingType == IPMI_TYPE_EVENT1)
    {
        return cmd->eventData1;
    }
    if(readingType == IPMI_TYPE_EVENT2)
    {
        return cmd->eventData2;
    }
    if (readingType == IPMI_TYPE_EVENT3)
    {
        return cmd->eventData3;
    }
    if (readingType == IPMI_TYPE_READING)
    {
        return cmd->reading;
    }
    return 0;
}

using Assertion = uint16_t;
using Deassertion = uint16_t;
using AssertionSet = std::pair<Assertion, Deassertion>;

AssertionSet getAssertionSet(SetSensorReadingReq *cmdData)
{

    Assertion assertionStates =
            (static_cast<Assertion>(cmdData->assertOffset8_14)) << 8 |
            cmdData->assertOffset0_7;
    Deassertion deassertionStates =
            (static_cast<Deassertion>(cmdData->deassertOffset8_14)) << 8 |
            cmdData->deassertOffset0_7; 
    return std::make_pair(assertionStates,deassertionStates);
}

uint8_t setInventorySensorReading(SetSensorReadingReq *cmdData,
                                 Info sensorInfo)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);


    auto& interfaceList = sensorInfo.sensorInterfaces;
    if (interfaceList.empty())
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    DbusInfo service;

    std::string intf = "xyz.openbmc_project.Inventory.Manager"s;
    try
    {
        service = getDbusInfo(bus, "xyz.openbmc_project.Inventory.Manager");
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    auto updMsg = bus.new_method_call(service.second.c_str(),
                                      service.first.c_str(),
                                      intf.c_str(),
                                     "Notify");
    ipmi::sensor::ObjectMap objects;
    ipmi::sensor::InterfaceMap interfaces;
    for (const auto& interface : interfaceList)
    {
        for (const auto& property : interface.second)
        {
            ipmi::sensor::PropertyMap props;
            bool valid = false;
            for (const auto& value : property.second)
            {
                if (assertionSet.test(value.first))
                {
                    props.emplace(property.first, std::move(value.second.assert));
                    valid = true;
                }
                else if (deassertionSet.test(value.first))
                {
                    props.emplace(property.first, value.second.deassert);
                    valid = true;
                }
            }
            if (valid)
            {
                interfaces.emplace(interface.first, std::move(props));
            }
        }
    }
    objects.emplace(sensorInfo.sensorPath, std::move(interfaces));
    updMsg.append(std::move(objects));

    try
    {
        auto serviceResponseMsg = bus.call(updMsg);
        if (serviceResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in set call");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}
uint8_t setPropertySensorReading(SetSensorReadingReq *cmdData,
                                 Info sensorInfo)
{
    std::bitset<16> assertionSet(getAssertionSet(cmdData).first);
    std::bitset<16> deassertionSet(getAssertionSet(cmdData).second);

    uint8_t setVal = sensorInfo.getSensorValue(cmdData);
    auto& rtype = sensorInfo.valueReadingType;

    auto& interfaceList = sensorInfo.sensorInterfaces;
    if (interfaceList.empty())
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    using namespace std::string_literals;
    DbusInfo service;

    auto& intf = interfaceList.begin()->first;
    try
    {
        service = getDbusInfo(bus, "org.freedesktop.DBus.Properties");
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    auto updMsg = bus.new_method_call(service.second.c_str(),
                                      service.first.c_str(),
                                      intf.c_str(),
                                     "Set");
    //for each interface in the list
    for (const auto& interface : interfaceList)
    {

        updMsg.append(interface.first);

        for (const auto& property : interface.second)
        {
            updMsg.append(property.first);

            if (rtype == IPMI_TYPE_READING)
            {
                updMsg.append(setVal);
                break;
            }
            for (const auto& value : property.second)
            {
                //for assertion type check whether bit is set.
                if (rtype == IPMI_TYPE_ASSERTION)
                {
                    if (assertionSet.test(value.first))
                    {
                        updMsg.append(value.second.assert);
                    }
                    if (deassertionSet.test(value.first))
                    {
                        updMsg.append(value.second.deassert);
                    }
                }
                else if (setVal == value.first)
                {
                        updMsg.append(value.second.assert);
                }
            }
        }
    }

    try
    {
        auto serviceResponseMsg = bus.call(updMsg);
        if (serviceResponseMsg.is_method_error())
        {
            log<level::ERR>("Error in set call");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

extern const IdInfoMap sensors = {
{3,{

        15,"/xyz/openbmc_project/state/boot/progress",111,1,0,0,
        0,"org.freedesktop.DBus.Properties",
        IPMI_TYPE_READING,setPropertySensorReading,std::bind(getValue, IPMI_TYPE_READING, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Boot.Progress",{
                {"ProgressStages",{
                    { 0,{
                                                   std::string("xyz.openbmc_project.State.Boot.Progress.BootProgress.ProgressStages.Unspecified"),
                                                     }
                    },
                    { 1,{
                                                   std::string("xyz.openbmc_project.State.Boot.Progress.BootProgress.ProgressStages.MemoryInit"),
                                                     }
                    },
                    { 19,{
                                                   std::string("xyz.openbmc_project.State.Boot.Progress.BootProgress.ProgressStages.OSStart"),
                                                     }
                    },
                    { 20,{
                                                   std::string("xyz.openbmc_project.State.Boot.Progress.BootProgress.ProgressStages.MotherboardInit"),
                                                     }
                    },
                    { 3,{
                                                   std::string("xyz.openbmc_project.State.Boot.Progress.BootProgress.ProgressStages.SecondaryProcInit"),
                                                     }
                    },
                }},
            }},
     }
}},
{5,{

        31,"/xyz/openbmc_project/state/host0/os_status",111,1,0,0,
        0,"org.freedesktop.DBus.Properties",
        IPMI_TYPE_ASSERTION,setPropertySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.OperatingSystem.Status",{
                {"OperatingSystemState",{
                    { 1,{
                                                   std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.CBoot"),
                                                     }
                    },
                    { 2,{
                                                   std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.PXEBoot"),
                                                     }
                    },
                    { 3,{
                                                   std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.DiagBoot"),
                                                     }
                    },
                    { 4,{
                                                   std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.CDROMBoot"),
                                                     }
                    },
                    { 5,{
                                                   std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.ROMBoot"),
                                                     }
                    },
                    { 6,{
                                                   std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.BootComplete"),
                                                     }
                    },
                }},
            }},
     }
}},
{7,{

        195,"/xyz/openbmc_project/control/host0/reboot_attempts",111,1,0,0,
        0,"org.freedesktop.DBus.Properties",
        IPMI_TYPE_READING,setPropertySensorReading,std::bind(getValue, IPMI_TYPE_READING, std::placeholders::_1),{
            {"xyz.openbmc_project.Control.Boot.RebootAttempts",{
                {"AttemptsLeft",{
                    { 255,{
                                                   std::string("set"),
                                                     }
                    },
                }},
            }},
     }
}},
{18,{

        7,"/system/chassis/motherboard/cpu0/core0",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{21,{

        7,"/system/chassis/motherboard/cpu0/core1",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{24,{

        7,"/system/chassis/motherboard/cpu0/core2",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{27,{

        7,"/system/chassis/motherboard/cpu0/core3",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{30,{

        7,"/system/chassis/motherboard/cpu0/core4",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{33,{

        7,"/system/chassis/motherboard/cpu0/core5",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{36,{

        7,"/system/chassis/motherboard/cpu0/core6",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{39,{

        7,"/system/chassis/motherboard/cpu0/core7",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{42,{

        7,"/system/chassis/motherboard/cpu0/core8",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{45,{

        7,"/system/chassis/motherboard/cpu0/core9",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{48,{

        7,"/system/chassis/motherboard/cpu0/core10",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{51,{

        7,"/system/chassis/motherboard/cpu0/core11",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{54,{

        7,"/system/chassis/motherboard/cpu0/core12",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{57,{

        7,"/system/chassis/motherboard/cpu0/core13",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{60,{

        7,"/system/chassis/motherboard/cpu0/core14",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{63,{

        7,"/system/chassis/motherboard/cpu0/core15",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{66,{

        7,"/system/chassis/motherboard/cpu0/core16",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{69,{

        7,"/system/chassis/motherboard/cpu0/core17",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{72,{

        7,"/system/chassis/motherboard/cpu0/core18",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{75,{

        7,"/system/chassis/motherboard/cpu0/core19",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{78,{

        7,"/system/chassis/motherboard/cpu0/core20",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{81,{

        7,"/system/chassis/motherboard/cpu0/core21",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{84,{

        7,"/system/chassis/motherboard/cpu0/core22",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{87,{

        7,"/system/chassis/motherboard/cpu0/core23",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{90,{

        7,"/system/chassis/motherboard/cpu0",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{92,{

        7,"/system/chassis/motherboard/cpu1/core0",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{95,{

        7,"/system/chassis/motherboard/cpu1/core1",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{98,{

        7,"/system/chassis/motherboard/cpu1/core2",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{101,{

        7,"/system/chassis/motherboard/cpu1/core3",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{104,{

        7,"/system/chassis/motherboard/cpu1/core4",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{107,{

        7,"/system/chassis/motherboard/cpu1/core5",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{110,{

        7,"/system/chassis/motherboard/cpu1/core6",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{113,{

        7,"/system/chassis/motherboard/cpu1/core7",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{116,{

        7,"/system/chassis/motherboard/cpu1/core8",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{119,{

        7,"/system/chassis/motherboard/cpu1/core9",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{122,{

        7,"/system/chassis/motherboard/cpu1/core10",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{125,{

        7,"/system/chassis/motherboard/cpu1/core11",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{128,{

        7,"/system/chassis/motherboard/cpu1/core12",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{131,{

        7,"/system/chassis/motherboard/cpu1/core13",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{134,{

        7,"/system/chassis/motherboard/cpu1/core14",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{137,{

        7,"/system/chassis/motherboard/cpu1/core15",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{140,{

        7,"/system/chassis/motherboard/cpu1/core16",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{143,{

        7,"/system/chassis/motherboard/cpu1/core17",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{146,{

        7,"/system/chassis/motherboard/cpu1/core18",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{149,{

        7,"/system/chassis/motherboard/cpu1/core19",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{152,{

        7,"/system/chassis/motherboard/cpu1/core20",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{155,{

        7,"/system/chassis/motherboard/cpu1/core21",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{158,{

        7,"/system/chassis/motherboard/cpu1/core22",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{161,{

        7,"/system/chassis/motherboard/cpu1/core23",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{164,{

        7,"/system/chassis/motherboard/cpu1",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{166,{

        12,"/system/chassis/motherboard/dimm0",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{168,{

        12,"/system/chassis/motherboard/dimm1",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{170,{

        12,"/system/chassis/motherboard/dimm2",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{172,{

        12,"/system/chassis/motherboard/dimm3",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{174,{

        12,"/system/chassis/motherboard/dimm4",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{176,{

        12,"/system/chassis/motherboard/dimm5",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{178,{

        12,"/system/chassis/motherboard/dimm6",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{180,{

        12,"/system/chassis/motherboard/dimm7",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{182,{

        12,"/system/chassis/motherboard/dimm8",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{184,{

        12,"/system/chassis/motherboard/dimm9",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{186,{

        12,"/system/chassis/motherboard/dimm10",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{188,{

        12,"/system/chassis/motherboard/dimm11",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{190,{

        12,"/system/chassis/motherboard/dimm12",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{192,{

        12,"/system/chassis/motherboard/dimm13",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{194,{

        12,"/system/chassis/motherboard/dimm14",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
{196,{

        12,"/system/chassis/motherboard/dimm15",111,1,0,0,
        0,"xyz.openbmc_project.Inventory.Manager",
        IPMI_TYPE_ASSERTION,setInventorySensorReading,std::bind(getValue, IPMI_TYPE_ASSERTION, std::placeholders::_1),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                                                                              false,
                                                                                   true,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                                                                              true,
                                                                                   false,
                        }
                    },
                }},
            }},
     }
}},
};


