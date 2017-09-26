// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"
#include "sensordatahandler.hpp"

using namespace ipmi::sensor;

extern const IdInfoMap sensors = {
{3,{

        15,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.State.Boot.Progress",111,1,
        0,0,0,set::eventdata2,get::eventdata2,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Boot.Progress",{
                {"BootProgress",{
                {
                },
                {
                    { 0,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.Unspecified"),
                        }
                    },
                    { 1,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.MemoryInit"),
                        }
                    },
                    { 19,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSStart"),
                        }
                    },
                    { 20,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.MotherboardInit"),
                        }
                    },
                    { 3,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.Boot.Progress.ProgressStages.SecondaryProcInit"),
                        }
                    },
                }}},
            }},
     }
}},
{5,{

        31,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.State.OperatingSystem.Status",111,1,
        0,0,0,set::assertion,get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.OperatingSystem.Status",{
                {"OperatingSystemState",{
                {
                },
                {
                    { 1,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.CBoot"),
                        }
                    },
                    { 2,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.PXEBoot"),
                        }
                    },
                    { 3,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.DiagBoot"),
                        }
                    },
                    { 4,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.CDROMBoot"),
                        }
                    },
                    { 5,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.ROMBoot"),
                        }
                    },
                    { 6,{
                            SkipAssertion::NONE,
                           std::string("xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.BootComplete"),
                        }
                    },
                }}},
            }},
     }
}},
{7,{

        195,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.Control.Boot.RebootAttempts",111,1,
        0,0,0,set::readingAssertion<uint32_t>,get::readingAssertion<uint32_t>,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.Control.Boot.RebootAttempts",{
                {"AttemptsLeft",{
                {
                },
                {
                    { 255,{
                            }},
                }}},
            }},
     }
}},
{11,{

        202,"/xyz/openbmc_project/control/host0/powersupply_redundancy","xyz.openbmc_project.Control.PowerSupply.Redundancy",3,1,
        0,0,0,set::assertion,get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.Control.PowerSupply.Redundancy",{
                {"PowerSupplyRedundancy",{
                {
                },
                {
                    { 0,{
                            SkipAssertion::NONE,
                           false,
                        }
                    },
                    { 1,{
                            SkipAssertion::NONE,
                           true,
                        }
                    },
                }}},
            }},
     }
}},
{18,{

        7,"/system/chassis/motherboard/cpu0/core0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{21,{

        7,"/system/chassis/motherboard/cpu0/core1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{24,{

        7,"/system/chassis/motherboard/cpu0/core2","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{27,{

        7,"/system/chassis/motherboard/cpu0/core3","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{30,{

        7,"/system/chassis/motherboard/cpu0/core4","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{33,{

        7,"/system/chassis/motherboard/cpu0/core5","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{36,{

        7,"/system/chassis/motherboard/cpu0/core6","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{39,{

        7,"/system/chassis/motherboard/cpu0/core7","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{42,{

        7,"/system/chassis/motherboard/cpu0/core8","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{45,{

        7,"/system/chassis/motherboard/cpu0/core9","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{48,{

        7,"/system/chassis/motherboard/cpu0/core10","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{51,{

        7,"/system/chassis/motherboard/cpu0/core11","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{54,{

        7,"/system/chassis/motherboard/cpu0/core12","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{57,{

        7,"/system/chassis/motherboard/cpu0/core13","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{60,{

        7,"/system/chassis/motherboard/cpu0/core14","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{63,{

        7,"/system/chassis/motherboard/cpu0/core15","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{66,{

        7,"/system/chassis/motherboard/cpu0/core16","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{69,{

        7,"/system/chassis/motherboard/cpu0/core17","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{72,{

        7,"/system/chassis/motherboard/cpu0/core18","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{75,{

        7,"/system/chassis/motherboard/cpu0/core19","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{78,{

        7,"/system/chassis/motherboard/cpu0/core20","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{81,{

        7,"/system/chassis/motherboard/cpu0/core21","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{84,{

        7,"/system/chassis/motherboard/cpu0/core22","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{87,{

        7,"/system/chassis/motherboard/cpu0/core23","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{90,{

        7,"/system/chassis/motherboard/cpu0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{92,{

        7,"/system/chassis/motherboard/cpu1/core0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{95,{

        7,"/system/chassis/motherboard/cpu1/core1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{98,{

        7,"/system/chassis/motherboard/cpu1/core2","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{101,{

        7,"/system/chassis/motherboard/cpu1/core3","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{104,{

        7,"/system/chassis/motherboard/cpu1/core4","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{107,{

        7,"/system/chassis/motherboard/cpu1/core5","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{110,{

        7,"/system/chassis/motherboard/cpu1/core6","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{113,{

        7,"/system/chassis/motherboard/cpu1/core7","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{116,{

        7,"/system/chassis/motherboard/cpu1/core8","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{119,{

        7,"/system/chassis/motherboard/cpu1/core9","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{122,{

        7,"/system/chassis/motherboard/cpu1/core10","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{125,{

        7,"/system/chassis/motherboard/cpu1/core11","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{128,{

        7,"/system/chassis/motherboard/cpu1/core12","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{131,{

        7,"/system/chassis/motherboard/cpu1/core13","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{134,{

        7,"/system/chassis/motherboard/cpu1/core14","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{137,{

        7,"/system/chassis/motherboard/cpu1/core15","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{140,{

        7,"/system/chassis/motherboard/cpu1/core16","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{143,{

        7,"/system/chassis/motherboard/cpu1/core17","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{146,{

        7,"/system/chassis/motherboard/cpu1/core18","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{149,{

        7,"/system/chassis/motherboard/cpu1/core19","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{152,{

        7,"/system/chassis/motherboard/cpu1/core20","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{155,{

        7,"/system/chassis/motherboard/cpu1/core21","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{158,{

        7,"/system/chassis/motherboard/cpu1/core22","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{161,{

        7,"/system/chassis/motherboard/cpu1/core23","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::DEASSERT,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{164,{

        7,"/system/chassis/motherboard/cpu1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 7,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 8,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 7,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{166,{

        12,"/system/chassis/motherboard/dimm0","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{168,{

        12,"/system/chassis/motherboard/dimm1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{170,{

        12,"/system/chassis/motherboard/dimm2","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{172,{

        12,"/system/chassis/motherboard/dimm3","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{174,{

        12,"/system/chassis/motherboard/dimm4","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{176,{

        12,"/system/chassis/motherboard/dimm5","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{178,{

        12,"/system/chassis/motherboard/dimm6","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{180,{

        12,"/system/chassis/motherboard/dimm7","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{182,{

        12,"/system/chassis/motherboard/dimm8","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{184,{

        12,"/system/chassis/motherboard/dimm9","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{186,{

        12,"/system/chassis/motherboard/dimm10","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{188,{

        12,"/system/chassis/motherboard/dimm11","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{190,{

        12,"/system/chassis/motherboard/dimm12","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{192,{

        12,"/system/chassis/motherboard/dimm13","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{194,{

        12,"/system/chassis/motherboard/dimm14","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{196,{

        12,"/system/chassis/motherboard/dimm15","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,inventory::get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.State.Decorator.OperationalStatus",{
                {"Functional",{
                {
                    { 6,{
                            true,
                            false,
                        }
                     },
                },
                {
                    { 4,{
                            SkipAssertion::NONE,
                           false,
                           true,
                        }
                    },
                }}},
            }},
            {"xyz.openbmc_project.Inventory.Item",{
                {"Present",{
                {
                },
                {
                    { 6,{
                            SkipAssertion::NONE,
                           true,
                           false,
                        }
                    },
                }}},
            }},
     }
}},
{215,{

        204,"/xyz/openbmc_project/control/host0/TPMEnable","xyz.openbmc_project.Control.TPM.Policy",3,1,
        0,0,0,set::assertion,get::assertion,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.Control.TPM.Policy",{
                {"TPMEnable",{
                {
                },
                {
                    { 0,{
                            SkipAssertion::NONE,
                           false,
                        }
                    },
                    { 1,{
                            SkipAssertion::NONE,
                           true,
                        }
                    },
                }}},
            }},
     }
}},
{216,{

        200,"/xyz/openbmc_project/control/host0/powersupply_derating","xyz.openbmc_project.Control.PowerSupply.Derating",111,1,
        0,0,0,set::readingAssertion<uint32_t>,get::readingAssertion<uint32_t>,Mutability(Mutability::Read),{
            {"xyz.openbmc_project.Control.PowerSupply.Derating",{
                {"PowerSupplyDerating",{
                {
                },
                {
                    { 255,{
                            }},
                }}},
            }},
     }
}},
};

