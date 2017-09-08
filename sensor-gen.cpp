// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"
#include "sensordatahandler.hpp"

using namespace ipmi::sensor;

extern const IdInfoMap sensors = {
{3,{

        15,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.State.Boot.Progress",111,1,
        0,0,0,set::eventdata2,get::eventdata2,{
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
                    { 3,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.SecondaryProcInit"),
                        }
                    },
                    { 20,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.MotherboardInit"),
                        }
                    },
                    { 19,{
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSStart"),
                        }
                    },
                }},
            }},
     }
}},
{5,{

        31,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.State.OperatingSystem.Status",111,1,
        0,0,0,set::assertion,get::assertion,{
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

        195,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.Control.Boot.RebootAttempts",111,1,
        0,0,0,set::readingAssertion<uint32_t>,get::readingAssertion<uint32_t>,{
            {"xyz.openbmc_project.Control.Boot.RebootAttempts",{
                {"AttemptsLeft",{
                    { 255,{
                            }},
                }},
            }},
     }
}},
{8,{

        9,"/org/open_power/control/occ0","org.open_power.OCC.Status",9,1,
        0,0,0,set::assertion,get::assertion,{
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

        9,"/org/open_power/control/occ1","org.open_power.OCC.Status",9,1,
        0,0,0,set::assertion,get::assertion,{
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

        7,"/system/chassis/motherboard/cpu0/core0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{21,{

        7,"/system/chassis/motherboard/cpu0/core1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{24,{

        7,"/system/chassis/motherboard/cpu0/core2","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{27,{

        7,"/system/chassis/motherboard/cpu0/core3","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{30,{

        7,"/system/chassis/motherboard/cpu0/core4","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{33,{

        7,"/system/chassis/motherboard/cpu0/core5","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{36,{

        7,"/system/chassis/motherboard/cpu0/core6","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{39,{

        7,"/system/chassis/motherboard/cpu0/core7","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{42,{

        7,"/system/chassis/motherboard/cpu0/core8","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{45,{

        7,"/system/chassis/motherboard/cpu0/core9","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{48,{

        7,"/system/chassis/motherboard/cpu0/core10","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{51,{

        7,"/system/chassis/motherboard/cpu0/core11","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{54,{

        7,"/system/chassis/motherboard/cpu0/core12","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{57,{

        7,"/system/chassis/motherboard/cpu0/core13","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{60,{

        7,"/system/chassis/motherboard/cpu0/core14","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{63,{

        7,"/system/chassis/motherboard/cpu0/core15","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{66,{

        7,"/system/chassis/motherboard/cpu0/core16","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{69,{

        7,"/system/chassis/motherboard/cpu0/core17","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{72,{

        7,"/system/chassis/motherboard/cpu0/core18","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{75,{

        7,"/system/chassis/motherboard/cpu0/core19","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{78,{

        7,"/system/chassis/motherboard/cpu0/core20","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{81,{

        7,"/system/chassis/motherboard/cpu0/core21","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{84,{

        7,"/system/chassis/motherboard/cpu0/core22","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{87,{

        7,"/system/chassis/motherboard/cpu0/core23","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{90,{

        7,"/system/chassis/motherboard/cpu0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{92,{

        7,"/system/chassis/motherboard/cpu1/core0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{95,{

        7,"/system/chassis/motherboard/cpu1/core1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{98,{

        7,"/system/chassis/motherboard/cpu1/core2","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{101,{

        7,"/system/chassis/motherboard/cpu1/core3","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{104,{

        7,"/system/chassis/motherboard/cpu1/core4","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{107,{

        7,"/system/chassis/motherboard/cpu1/core5","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{110,{

        7,"/system/chassis/motherboard/cpu1/core6","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{113,{

        7,"/system/chassis/motherboard/cpu1/core7","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{116,{

        7,"/system/chassis/motherboard/cpu1/core8","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{119,{

        7,"/system/chassis/motherboard/cpu1/core9","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{122,{

        7,"/system/chassis/motherboard/cpu1/core10","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{125,{

        7,"/system/chassis/motherboard/cpu1/core11","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{128,{

        7,"/system/chassis/motherboard/cpu1/core12","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{131,{

        7,"/system/chassis/motherboard/cpu1/core13","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{134,{

        7,"/system/chassis/motherboard/cpu1/core14","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{137,{

        7,"/system/chassis/motherboard/cpu1/core15","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{140,{

        7,"/system/chassis/motherboard/cpu1/core16","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{143,{

        7,"/system/chassis/motherboard/cpu1/core17","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{146,{

        7,"/system/chassis/motherboard/cpu1/core18","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{149,{

        7,"/system/chassis/motherboard/cpu1/core19","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{152,{

        7,"/system/chassis/motherboard/cpu1/core20","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{155,{

        7,"/system/chassis/motherboard/cpu1/core21","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{158,{

        7,"/system/chassis/motherboard/cpu1/core22","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{161,{

        7,"/system/chassis/motherboard/cpu1/core23","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{164,{

        7,"/system/chassis/motherboard/cpu1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 7,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 8,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{166,{

        12,"/system/chassis/motherboard/dimm0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{168,{

        12,"/system/chassis/motherboard/dimm1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{170,{

        12,"/system/chassis/motherboard/dimm2","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{172,{

        12,"/system/chassis/motherboard/dimm3","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{174,{

        12,"/system/chassis/motherboard/dimm4","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{176,{

        12,"/system/chassis/motherboard/dimm5","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{178,{

        12,"/system/chassis/motherboard/dimm6","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{180,{

        12,"/system/chassis/motherboard/dimm7","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{182,{

        12,"/system/chassis/motherboard/dimm8","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{184,{

        12,"/system/chassis/motherboard/dimm9","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{186,{

        12,"/system/chassis/motherboard/dimm10","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{188,{

        12,"/system/chassis/motherboard/dimm11","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{190,{

        12,"/system/chassis/motherboard/dimm12","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{192,{

        12,"/system/chassis/motherboard/dimm13","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{194,{

        12,"/system/chassis/motherboard/dimm14","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{196,{

        12,"/system/chassis/motherboard/dimm15","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,{
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                    { 6,{
                           true,
                           false,
                        }
                    },
                }},
            }},
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                    { 4,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{215,{

        204,"/xyz/openbmc_project/control/host0/TPMEnable","xyz.openbmc_project.Control.TPM.Policy",3,1,
        0,0,0,set::assertion,get::assertion,{
            {"xyz.openbmc_project.Control.TPM.Policy",{
                {"TPMEnable",{
                    { 0,{
                           false,
                        }
                    },
                    { 1,{
                           true,
                        }
                    },
                }},
            }},
     }
}},
};

