
// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!
#include <bitset>
#include "types.hpp"
#include "host-ipmid/ipmid-api.h"
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include "sensordatahandler.hpp"

namespace ipmi
{
namespace sensor
{


namespace sensor_set
{
namespace sensortype12
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = Notify::makeDbusMsg(
                    "xyz.openbmc_project.Inventory.Manager",
                    "/system/chassis/motherboard/dimm15",
                    "Notify");

    auto interfaceList = sensorInfo.sensorInterfaces;
    auto l_ret = Notify::assertion(msg,
                        interfaceList,
                        "/system/chassis/motherboard/dimm15", cmdData);
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype12

namespace sensortype15
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = Set::makeDbusMsg(
                    "org.freedesktop.DBus.Properties",
                    "/xyz/openbmc_project/state/host0",
                    "Set");

    auto interfaceList = sensorInfo.sensorInterfaces;
    auto l_ret = Set::discreteSignal(msg,
                        interfaceList,
                        cmdData->eventData2);
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype15

namespace sensortype195
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = Set::makeDbusMsg(
                    "org.freedesktop.DBus.Properties",
                    "/xyz/openbmc_project/state/host0",
                    "Set");

    auto interfaceList = sensorInfo.sensorInterfaces;
    auto l_ret = Set::sendData(msg,
                        interfaceList,
                        static_cast<uint32_t>(cmdData->reading));
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype195

namespace sensortype31
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = Set::makeDbusMsg(
                    "org.freedesktop.DBus.Properties",
                    "/xyz/openbmc_project/state/host0",
                    "Set");

    auto interfaceList = sensorInfo.sensorInterfaces;
    auto l_ret = Set::assertion(msg,
                        interfaceList,
                        "/xyz/openbmc_project/state/host0", cmdData);
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype31

namespace sensortype7
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = Notify::makeDbusMsg(
                    "xyz.openbmc_project.Inventory.Manager",
                    "/system/chassis/motherboard/cpu1",
                    "Notify");

    auto interfaceList = sensorInfo.sensorInterfaces;
    auto l_ret = Notify::assertion(msg,
                        interfaceList,
                        "/system/chassis/motherboard/cpu1", cmdData);
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype7

namespace sensortype9
{

ipmi_ret_t update(SetSensorReadingReq* cmdData,
                  Info sensorInfo)
{
    auto msg = Set::makeDbusMsg(
                    "org.freedesktop.DBus.Properties",
                    "/org/open_power/control/occ1",
                    "Set");

    auto interfaceList = sensorInfo.sensorInterfaces;
    auto l_ret = Set::assertion(msg,
                        interfaceList,
                        "/org/open_power/control/occ1", cmdData);
    if (l_ret != IPMI_CC_OK)
    {
        return l_ret;
    }
    return updateToDbus(msg); 
}
}//namespace sensortype9

}//namespace sensor_get
}//namespace sensor
}//namespace ipmi

using namespace ipmi::sensor;
extern const IdInfoMap sensors = {
{3,{

        15,"/xyz/openbmc_project/state/host0",111,1,0,0,
        0,sensor_set::sensortype15::update,{
            {"xyz.openbmc_project.State.Boot.Progress",{
                {"BootProgress",{
                    { 0,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.Unspecified"),
                        }
                    },
                    { 1,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.MemoryInit"),
                        }
                    },
                    { 19,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSStart"),
                        }
                    },
                    { 20,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.MotherboardInit"),
                        }
                    },
                    { 3,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.SecondaryProcInit"),
                        }
                    },
                }},
            }},
     }
}},
{5,{

        31,"/xyz/openbmc_project/state/host0",111,1,0,0,
        0,sensor_set::sensortype31::update,{
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

        195,"/xyz/openbmc_project/state/host0",111,1,0,0,
        0,sensor_set::sensortype195::update,{
            {"xyz.openbmc_project.Control.Boot.RebootAttempts",{
                {"AttemptsLeft",{
                    { 255,{
                            }},
                }},
            }},
     }
}},
{8,{

        9,"/org/open_power/control/occ0",9,1,0,0,
        0,sensor_set::sensortype9::update,{
            {"org.open_power.OCC.Status",{
                {"OccActive",{
                    { 0,{
                           false,
                           true,
                        }
                    },
                    { 1,{
                           true,
                           false,
                        }
                    },
                }},
            }},
     }
}},
{9,{

        9,"/org/open_power/control/occ1",9,1,0,0,
        0,sensor_set::sensortype9::update,{
            {"org.open_power.OCC.Status",{
                {"OccActive",{
                    { 0,{
                           false,
                           true,
                        }
                    },
                    { 1,{
                           true,
                           false,
                        }
                    },
                }},
            }},
     }
}},
{18,{

        7,"/system/chassis/motherboard/cpu0/core0",111,1,0,0,
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype7::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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
        0,sensor_set::sensortype12::update,{
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

