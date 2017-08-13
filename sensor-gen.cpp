// !!! WARNING: This is a GENERATED Code..Please do NOT Edit !!!

#include "types.hpp"
#include "sensordatahandler.hpp"

using namespace ipmi::sensor;

namespace sensor_98
{

inline ipmi_ret_t readingAssertion(const SetSensorReadingReq& cmdData,
                            const Info& sensorInfo)
{
    return set::readingAssertion<uint32_t>(cmdData, sensorInfo);
}

} // namespace sensor_98

namespace sensor_99
{

inline ipmi_ret_t readingAssertion(const SetSensorReadingReq& cmdData,
                            const Info& sensorInfo)
{
    return set::readingAssertion<uint32_t>(cmdData, sensorInfo);
}

} // namespace sensor_99


extern const IdInfoMap sensors = {
{96,{

        7,"/org/open_power/control/occ0","org.open_power.OCC.Status",111,1,
        0,0,0,set::assertion,{
            {"org.open_power.OCC.Status",{
                {"OccActive",{
                    { 6,{
                           false,
                           true,
                        }
                    },
                }},
            }},
     }
}},
{97,{

        4,"/system/chassis/motherboard/dimm1","xyz.openbmc_project.Inventory.Manager",111,1,
        0,0,0,notify::assertion,{
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
{98,{

        195,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.Control.Boot.RebootAttempts",111,1,
        0,0,0,sensor_98::readingAssertion,{
            {"xyz.openbmc_project.Control.Boot.RebootAttempts",{
                {"AttemptsLeft",{
                    { 255,{
                            }},
                }},
            }},
     }
}},
{99,{

        195,"/xyz/openbmc_project/state/host0","xyz.openbmc_project.Control.Boot.RebootAttempts",111,1,
        0,0,0,sensor_99::readingAssertion,{
            {"xyz.openbmc_project.Control.Boot.RebootAttempts",{
                {"AttemptsLeft",{
                    { 255,{
                            }},
                }},
            }},
     }
}},
};

