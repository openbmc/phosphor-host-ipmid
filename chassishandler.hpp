#pragma once

#include <stdint.h>

#include <cstddef>
#include <xyz/openbmc_project/State/Chassis/server.hpp>
#include <xyz/openbmc_project/State/Host/server.hpp>

// Phosphor State manager
namespace State = sdbusplus::xyz::openbmc_project::State::server;

// IPMI commands for Chassis net functions.
enum ipmi_netfn_chassis_cmds
{
    IPMI_CMD_GET_CHASSIS_CAP = 0x00,
    // Chassis Status
    IPMI_CMD_CHASSIS_STATUS = 0x01,
    // Chassis Control
    IPMI_CMD_CHASSIS_CONTROL = 0x02,
    IPMI_CMD_CHASSIS_IDENTIFY = 0x04,
    IPMI_CMD_SET_CHASSIS_CAP = 0x05,
    // Get capability bits
    IPMI_CMD_SET_SYS_BOOT_OPTIONS = 0x08,
    IPMI_CMD_GET_SYS_BOOT_OPTIONS = 0x09,
    IPMI_CMD_GET_POH_COUNTER = 0x0F,
};

// Command specific completion codes
enum ipmi_chassis_return_codes
{
    IPMI_OK = 0x0,
    IPMI_CC_PARM_NOT_SUPPORTED = 0x80,
};

// Generic completion codes,
// see IPMI doc section 5.2
enum ipmi_generic_return_codes
{
    IPMI_OUT_OF_SPACE = 0xC4,
};

// Various Chassis operations under a single command.
enum ipmi_chassis_control_cmds : uint8_t
{
    CMD_POWER_OFF = 0x00,
    CMD_POWER_ON = 0x01,
    CMD_POWER_CYCLE = 0x02,
    CMD_HARD_RESET = 0x03,
    CMD_PULSE_DIAGNOSTIC_INTR = 0x04,
    CMD_SOFT_OFF_VIA_OVER_TEMP = 0x05,
};
enum class BootOptionParameter : size_t
{
    bootInfo = 0x4,
    bootFlags = 0x5,
    opalNetworkSettings = 0x61
};

enum class BootOptionResponseSize : size_t
{
    bootFlags = 5,
    opalNetworkSettings = 50
};

enum class ChassisIDState : uint8_t
{
    off = 0x0,
    temporaryOn = 0x1,
    indefiniteOn = 0x2,
    reserved = 0x3
};

namespace ipmi
{

namespace softoff
{
static constexpr auto propRespReceived = "ResponseReceived";
static constexpr auto valHostShutdown =
    "xyz.openbmc_project.Ipmi.Internal."
    "SoftPowerOff.HostResponse.HostShutdown";

/** @brief Send a command to SoftPowerOff application to stop any timer
 *
 */
bool stopSoftOffTimer();

/** @brief Create file to indicate there is no need for
 *         softoff notification to the host
 *
 */
void indicateNoSoftoffNeeded();

} // namespace softoff

namespace chassis
{
// OpenBMC Chassis State Manager dbus framework
static constexpr auto stateMgrRoot = "/xyz/openbmc_project/state/chassis0";
static constexpr auto stateMgrServiceIface =
    "xyz.openbmc_project.State.Chassis";
static constexpr auto propReqTrans = "RequestedPowerTransition";
static constexpr auto propCurrentState = "CurrentPowerState";
static constexpr auto valStateOff =
    "xyz.openbmc_project.State.Chassis.PowerState.Off";
static constexpr auto valStateOn =
    "xyz.openbmc_project.State.Chassis.PowerState.On";

/** @brief Initialize the Chassis State transition
 *
 *  @param[in] bus - The bus used for calling the method
 *  @param[in] transition - The state to perform transition to
 *  @return On success returns True, on failure - False
 */
bool initStateTransition(State::Chassis::Transition transition);

/** @brief Get the value of the Chassis State
 *
 *  @param[in] bus - The bus used for calling the method
 *  @return On success returns the value of the property.
 */
std::string getChassisState();

} // namespace chassis

namespace host
{
// Since the timer is set to be periodic with 1sec interval,
// introduce the timeout of 10 seconds
static constexpr uint8_t TRANSITION_TIMEOUT = 10;
static constexpr auto stateMgrRoot = "/xyz/openbmc_project/state/host0";
static constexpr auto stateMgrServiceIface = "xyz.openbmc_project.State.Host";
static constexpr auto propReqTrans = "RequestedHostTransition";
static constexpr auto propCurrentState = "CurrentHostState";
static constexpr auto valStateOff =
    "xyz.openbmc_project.State.Host.HostState.Off";
static constexpr auto valTransOff =
    "xyz.openbmc_project.State.Host.Transition.Off";

/** @brief Initialize the Host State transition
 *
 *  @param[in] bus - The bus used for calling the method
 *  @param[in] transition - The state to perform transition to
 *  @return On success returns True, on failure - False
 */
bool initStateTransition(State::Host::Transition transition);

/** @brief Get the value of the Host State
 *
 *  @param[in] bus - The bus used for calling the method
 *  @return On success returns the value of the property.
 */
std::string getHostState();

/** @brief Get the value of the RequestedHostTransition
 *
 *  @param[in] bus - The bus used for calling the method
 *  @return On success returns the value of the property.
 */
std::string getHostTransition();

} // namespace host
} // namespace ipmi
