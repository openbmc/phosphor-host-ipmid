/**
 * Copyright © 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <any>
#include <ipmi/filter.hpp>
#include <ipmi/handler.hpp>
#include <ipmi/ipmi-api.hpp>

namespace ipmi
{

namespace impl
{

// IPMI command handler registration implementation
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
                     ::ipmi::HandlerBase::ptr handler, std::any& ctx);
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
                          ::ipmi::HandlerBase::ptr handler, std::any& ctx);
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
                        ::ipmi::HandlerBase::ptr handler, std::any& ctx);

// IPMI command filter registration implementation
void registerFilter(int prio, ::ipmi::FilterBase::ptr filter, std::any& ctx);

} // namespace impl

template <typename Handler>
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
                     Handler&& handler)
{
    auto h = ipmi::makeHandler(std::forward<Handler>(handler));
    // use an empty std::any for context since none was passed in
    std::any empty;
    impl::registerHandler(prio, netFn, cmd, priv, h, empty);
}

template <typename Handler, typename Context>
void registerHandler(int prio, NetFn netFn, Cmd cmd, Privilege priv,
                     Handler&& handler, Context& ctx)
{
    auto h = ipmi::makeHandler(handler);
    // add in a std::any(ctx) to the mix
    impl::registerHandler(prio, netFn, cmd, priv, h, std::any(ctx));
}

/* From IPMI 2.0 spec Network Function Codes Table (Row 2Ch):
    The first data byte position in requests and respo nses under this network
    function identifies the defining body that specifies command functionality.
    Software assumes that the command and completion code field positions will
    hold command and completion code values.

    The following values are used to ident ify the defining body:
    00h PICMG - PCI Industrial Computer Manufacturer’s Group.  ( www.picmg.com )
    01h DMTF Pre-OS Working Group ASF Specification ( www.dmtf.org )
    02h Server System Infrastructure (SSI) Forum ( www.ssiforum.org )
    03h VITA Standards Organization (VSO) (www.vita.com)
    DCh DCMI Specifications ( www.intel.com/go/dcmi )
    all other Reserved

    When this network function is used, the ID for the defining body occupies
    the first data byte in a request, and the second data byte (following the
    completion code) in a response.
 */
template <typename Handler>
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
                          Handler&& handler)
{
    auto h = ipmi::makeHandler(handler);
    // use an empty std::any for context since none was passed in
    std::any empty;
    impl::registerGroupHandler(prio, group, cmd, priv, h, empty);
}

template <typename Handler, typename Context>
void registerGroupHandler(int prio, Group group, Cmd cmd, Privilege priv,
                          Handler&& handler, Context& ctx)
{
    auto h = ipmi::makeHandler(handler);
    // add in a std::any(ctx) to the mix
    impl::registerGroupHandler(prio, group, cmd, priv, h, std::any(ctx));
}

/* From IPMI spec Network Function Codes Table (Row 2Eh):
    The first three data bytes of requests and responses under this network
    function explicitly identify the OEM or non -IPMI group that specifies the
    command functionality. While the OEM or non -IPMI group defines the
    functional semantics for the cmd and remaining data fields, the cmd field
    is required to hold the same value in requests and responses for a given
    operation in order to be supported under the IPMI message handling and
    transport mechanisms.

    When this network function is used, the IANA Enterprise Number for the
    defining body occupies the first three data bytes in a request, and the
    first three data bytes following the completion code position in a
    response.
 */
template <typename Handler>
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
                        Handler&& handler)
{
    auto h = ipmi::makeHandler(handler);
    // use an empty std::any for context since none was passed in
    std::any empty;
    impl::registerOemHandler(prio, iana, cmd, priv, h, empty);
}

template <typename Handler, typename Context>
void registerOemHandler(int prio, Iana iana, Cmd cmd, Privilege priv,
                        Handler&& handler, Context& ctx)
{
    auto h = ipmi::makeHandler(handler);
    // add in a std::any(ctx) to the mix
    impl::registerOemHandler(prio, iana, cmd, priv, h, std::any(ctx));
}

template <typename Filter>
void registerFilter(int prio, Filter&& filter)
{
    auto f = ipmi::makeFilter(filter);
    // use an empty std::any for context since none was passed in
    std::any empty;
    impl::registerFilter(prio, f, empty);
}

template <typename Filter, typename Context>
void registerFilter(int prio, Filter&& filter, Context& ctx)
{
    auto f = ipmi::makeFilter(filter);
    // add in a std::any(ctx) to the mix
    impl::registerFilter(prio, f, std::any(ctx));
}
} // namespace ipmi

#ifdef ALLOW_DEPRECATED_API
/* TODO: deprecated function: print warning once no more *internal*
 *       IPMI command handlers use this; delete it a year after that.
 */
// [[deprecated("Use ipmi::registerHandler() instead")]]
void ipmi_register_callback(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
                            ipmi_context_t context, ipmid_callback_t handler,
                            ipmi_cmd_privilege_t priv);

#endif /* ALLOW_DEPRECATED_API */

// IPMI 2.0 and DCMI 1.5 standard commands, namespaced by NetFn
// OEM and non-standard commands should be defined where they are used
namespace ipmi
{
namespace app
{
// 0x00 reserved
constexpr Cmd cmdGetDeviceId = 0x01;
constexpr Cmd cmdColdReset = 0x02;
constexpr Cmd cmdWarmReset = 0x03;
constexpr Cmd cmdGetSelfTestResults = 0x04;
constexpr Cmd cmdManufacturingTestOn = 0x05;
constexpr Cmd cmdSetAcpiPowerState = 0x06;
constexpr Cmd cmdGetAcpiPowerState = 0x07;
constexpr Cmd cmdGetDeviceGuid = 0x08;
constexpr Cmd cmdGetNetFnSupport = 0x09;
constexpr Cmd cmdGetCmdSupport = 0x0A;
constexpr Cmd cmdGetCmdSubFnSupport = 0x0B;
constexpr Cmd cmdGetConfigurableCmds = 0x0C;
constexpr Cmd cmdGetConfigurableCmdSubFns = 0x0D;
// 0x0E-0x21 unassigned
constexpr Cmd cmdResetWatchdogTimer = 0x22;
// 0x23 unassigned
constexpr Cmd cmdSetWatchdogTimer = 0x24;
constexpr Cmd cmdGetWatchdogTimer = 0x25;
// 0x26-0x2D unassigned
constexpr Cmd cmdSetBmcGlobalEnables = 0x2E;
constexpr Cmd cmdGetBmcGlobalEnables = 0x2F;
constexpr Cmd cmdClearMessageFlags = 0x30;
constexpr Cmd cmdGetMessageFlags = 0x31;
constexpr Cmd cmdEnableMessageChannelRcv = 0x32;
constexpr Cmd cmdGetMessage = 0x33;
constexpr Cmd cmdSendMessage = 0x34;
constexpr Cmd cmdReadEventMessageBuffer = 0x35;
constexpr Cmd cmdGetBtIfaceCapabilities = 0x36;
constexpr Cmd cmdGetSystemGuid = 0x37;
constexpr Cmd cmdGetChannelAuthCapabilities = 0x38;
constexpr Cmd cmdGetSessionChallenge = 0x39;
constexpr Cmd cmdActivateSession = 0x3A;
constexpr Cmd cmdSetSessionPrivilegeLevel = 0x3B;
constexpr Cmd cmdCloseSession = 0x3C;
constexpr Cmd cmdGetSessionInfo = 0x3D;
// 0x3E unassigned
constexpr Cmd cmdGetAuthCode = 0x3F;
constexpr Cmd cmdSetChannelAccess = 0x40;
constexpr Cmd cmdGetChannelAccess = 0x41;
constexpr Cmd cmdGetChannelInfoCommand = 0x42;
constexpr Cmd cmdSetUserAccessCommand = 0x43;
constexpr Cmd cmdGetUserAccessCommand = 0x44;
constexpr Cmd cmdSetUserName = 0x45;
constexpr Cmd cmdGetUserNameCommand = 0x46;
constexpr Cmd cmdSetUserPasswordCommand = 0x47;
constexpr Cmd cmdActivatePayload = 0x48;
constexpr Cmd cmdDeactivatePayload = 0x49;
constexpr Cmd cmdGetPayloadActivationStatus = 0x4A;
constexpr Cmd cmdGetPayloadInstanceInfo = 0x4B;
constexpr Cmd cmdSetUserPayloadAccess = 0x4C;
constexpr Cmd cmdGetUserPayloadAccess = 0x4D;
constexpr Cmd cmdGetChannelPayloadSupport = 0x4E;
constexpr Cmd cmdGetChannelPayloadVersion = 0x4F;
constexpr Cmd cmdGetChannelOemPayloadInfo = 0x50;
// 0x51 unassigned
constexpr Cmd cmdMasterWriteRead = 0x52;
// 0x53 unassigned
constexpr Cmd cmdGetChannelCipherSuites = 0x54;
constexpr Cmd cmdSuspendResumePayloadEnc = 0x55;
constexpr Cmd cmdSetChannelSecurityKeys = 0x56;
constexpr Cmd cmdGetSystemIfCapabilities = 0x57;
constexpr Cmd cmdSetSystemInfoParameters = 0x58;
constexpr Cmd cmdGetSystemInfoParameters = 0x59;
// 0x5A-0x5F unassigned
constexpr Cmd cmdSetCommandEnables = 0x60;
constexpr Cmd cmdGetCommandEnables = 0x61;
constexpr Cmd cmdSetCommandSubFnEnables = 0x62;
constexpr Cmd cmdGetCommandSubFnEnables = 0x63;
constexpr Cmd cmdGetOemNetFnIanaSupport = 0x64;
// 0x65-0xff unassigned
} // namespace app

namespace chassis
{
constexpr Cmd cmdGetChassisCapabilities = 0x00;
constexpr Cmd cmdGetChassisStatus = 0x01;
constexpr Cmd cmdChassisControl = 0x02;
constexpr Cmd cmdChassisReset = 0x03;
constexpr Cmd cmdChassisIdentify = 0x04;
constexpr Cmd cmdSetChassisCapabilities = 0x05;
constexpr Cmd cmdSetPowerRestorePolicy = 0x06;
constexpr Cmd cmdGetSystemRestartCause = 0x07;
constexpr Cmd cmdSetSystemBootOptions = 0x08;
constexpr Cmd cmdGetSystemBootOptions = 0x09;
constexpr Cmd cmdSetFrontPanelButtonEnables = 0x0A;
constexpr Cmd cmdSetPowerCycleInterval = 0x0B;
// 0x0C-0x0E unassigned
constexpr Cmd cmdGetPohCounter = 0x0F;
// 0x10-0xFF unassigned
} // namespace chassis

namespace sensor_event
{
constexpr Cmd cmdSetEventReceiver = 0x00;
constexpr Cmd cmdGetEventReceiver = 0x01;
constexpr Cmd cmdPlatformEvent = 0x02;
// 0x03-0x0F unassigned
constexpr Cmd cmdGetPefCapabilities = 0x10;
constexpr Cmd cmdArmPefPostponeTimer = 0x11;
constexpr Cmd cmdSetPefConfigurationParams = 0x12;
constexpr Cmd cmdGetPefConfigurationParams = 0x13;
constexpr Cmd cmdSetLastProcessedEventId = 0x14;
constexpr Cmd cmdGetLastProcessedEventId = 0x15;
constexpr Cmd cmdAlertImmediate = 0x16;
constexpr Cmd cmdPetAcknowledge = 0x17;
constexpr Cmd cmdGetDeviceSdrInfo = 0x20;
constexpr Cmd cmdGetDeviceSdr = 0x21;
constexpr Cmd cmdReserveDeviceSdrRepository = 0x22;
constexpr Cmd cmdGetSensorReadingFactors = 0x23;
constexpr Cmd cmdSetSensorHysteresis = 0x24;
constexpr Cmd cmdGetSensorHysteresis = 0x25;
constexpr Cmd cmdSetSensorThreshold = 0x26;
constexpr Cmd cmdGetSensorThreshold = 0x27;
constexpr Cmd cmdSetSensorEventEnable = 0x28;
constexpr Cmd cmdGetSensorEventEnable = 0x29;
constexpr Cmd cmdRearmSensorEvents = 0x2A;
constexpr Cmd cmdGetSensorEventStatus = 0x2B;
constexpr Cmd cmdGetSensorReading = 0x2D;
constexpr Cmd cmdSetSensorType = 0x2E;
constexpr Cmd cmdGetSensorType = 0x2F;
constexpr Cmd cmdSetSensorReadingAndEvtSts = 0x30;
// 0x31-0xFF unassigned
} // namespace sensor_event

namespace storage
{
// 0x00-0x0F unassigned
constexpr Cmd cmdGetFruInventoryAreaInfo = 0x10;
constexpr Cmd cmdReadFruData = 0x11;
constexpr Cmd cmdWriteFruData = 0x12;
// 0x13-0x1F unassigned
constexpr Cmd cmdGetSdrRepositoryInfo = 0x20;
constexpr Cmd cmdGetSdrRepositoryAllocInfo = 0x21;
constexpr Cmd cmdReserveSdrRepository = 0x22;
constexpr Cmd cmdGetSdr = 0x23;
constexpr Cmd cmdAddSdr = 0x24;
constexpr Cmd cmdPartialAddSdr = 0x25;
constexpr Cmd cmdDeleteSdr = 0x26;
constexpr Cmd cmdClearSdrRepository = 0x27;
constexpr Cmd cmdGetSdrRepositoryTime = 0x28;
constexpr Cmd cmdSetSdrRepositoryTime = 0x29;
constexpr Cmd cmdEnterSdrRepoUpdateMode = 0x2A;
constexpr Cmd cmdExitSdrReposUpdateMode = 0x2B;
constexpr Cmd cmdRunInitializationAgent = 0x2C;
// 0x2D-0x3F unassigned
constexpr Cmd cmdGetSelInfo = 0x40;
constexpr Cmd cmdGetSelAllocationInfo = 0x41;
constexpr Cmd cmdReserveSel = 0x42;
constexpr Cmd cmdGetSelEntry = 0x43;
constexpr Cmd cmdAddSelEntry = 0x44;
constexpr Cmd cmdPartialAddSelEntry = 0x45;
constexpr Cmd cmdDeleteSelEntry = 0x46;
constexpr Cmd cmdClearSel = 0x47;
constexpr Cmd cmdGetSelTime = 0x48;
constexpr Cmd cmdSetSelTime = 0x49;
constexpr Cmd cmdGetAuxiliaryLogStatus = 0x5A;
constexpr Cmd cmdSetAuxiliaryLogStatus = 0x5B;
constexpr Cmd cmdGetSelTimeUtcOffset = 0x5C;
constexpr Cmd cmdSetSelTimeUtcOffset = 0x5D;
// 0x5E-0xFF unassigned
} // namespace storage

namespace transport
{
constexpr Cmd cmdSetLanConfigParameters = 0x01;
constexpr Cmd cmdGetLanConfigParameters = 0x02;
constexpr Cmd cmdSuspendBmcArps = 0x03;
constexpr Cmd cmdGetIpUdpRmcpStatistics = 0x04;
constexpr Cmd cmdSetSerialModemConfig = 0x10;
constexpr Cmd cmdGetSerialModemConfig = 0x11;
constexpr Cmd cmdSetSerialModemMux = 0x12;
constexpr Cmd cmdGetTapResponseCodes = 0x13;
constexpr Cmd cmdSetPppUdpProxyTransmitData = 0x14;
constexpr Cmd cmdGetPppUdpProxyTransmitData = 0x15;
constexpr Cmd cmdSendPppUdpProxyPacket = 0x16;
constexpr Cmd cmdGetPppUdpProxyReceiveData = 0x17;
constexpr Cmd cmdSerialModemConnActive = 0x18;
constexpr Cmd cmdCallback = 0x19;
constexpr Cmd cmdSetUserCallbackOptions = 0x1A;
constexpr Cmd cmdGetUserCallbackOptions = 0x1B;
constexpr Cmd cmdSetSerialRoutingMux = 0x1C;
constexpr Cmd cmdSolActivating = 0x20;
constexpr Cmd cmdSetSolConfigParameters = 0x21;
constexpr Cmd cmdGetSolConfigParameters = 0x22;
constexpr Cmd cmdForwardedCommand = 0x30;
constexpr Cmd cmdSetForwardedCommands = 0x31;
constexpr Cmd cmdGetForwardedCommands = 0x32;
constexpr Cmd cmdEnableForwardedCommands = 0x33;
} // namespace transport

namespace bridge
{
constexpr Cmd cmdGetBridgeState = 0x00;
constexpr Cmd cmdSetBridgeState = 0x01;
constexpr Cmd cmdGetIcmbAddress = 0x02;
constexpr Cmd cmdSetIcmbAddress = 0x03;
constexpr Cmd cmdSetBridgeProxyAddress = 0x04;
constexpr Cmd cmdGetBridgeStatistics = 0x05;
constexpr Cmd cmdGetIcmbCapabilities = 0x06;
constexpr Cmd cmdClearBridgeStatistics = 0x08;
constexpr Cmd cmdGetBridgeProxyAddress = 0x09;
constexpr Cmd cmdGetIcmbConnectorInfo = 0x0A;
constexpr Cmd cmdGetIcmbConnectionId = 0x0B;
constexpr Cmd cmdSendIcmbConnectionId = 0x0C;
constexpr Cmd cmdPrepareForDiscovery = 0x10;
constexpr Cmd cmdGetAddresses = 0x11;
constexpr Cmd cmdSetDiscovered = 0x12;
constexpr Cmd cmdGetChassisDeviceId = 0x13;
constexpr Cmd cmdSetChassisDeviceId = 0x14;
constexpr Cmd cmdBridgeRequest = 0x20;
constexpr Cmd cmdBridgeMessage = 0x21;
// 0x22-0x2F unassigned
constexpr Cmd cmdGetEventCount = 0x30;
constexpr Cmd cmdSetEventDestination = 0x31;
constexpr Cmd cmdSetEventReceptionState = 0x32;
constexpr Cmd cmdSendIcmbEventMessage = 0x33;
constexpr Cmd cmdGetEventDestination = 0x34;
constexpr Cmd cmdGetEventReceptionState = 0x35;
// 0xC0-0xFE OEM Commands
constexpr Cmd cmdErrorReport = 0xFF;
} // namespace bridge

namespace dcmi
{
constexpr Cmd cmdGetDcmiCapabilitiesInfo = 0x01;
constexpr Cmd cmdGetPowerReading = 0x02;
constexpr Cmd cmdGetPowerLimit = 0x03;
constexpr Cmd cmdSetPowerLimit = 0x04;
constexpr Cmd cmdActDeactivatePwrLimit = 0x05;
constexpr Cmd cmdGetAssetTag = 0x06;
constexpr Cmd cmdGetDcmiSensorInfo = 0x07;
constexpr Cmd cmdSetAssetTag = 0x08;
constexpr Cmd cmdGetMgmtCntlrIdString = 0x09;
constexpr Cmd cmdSetMgmtCntlrIdString = 0x0A;
constexpr Cmd cmdSetThermalLimit = 0x0B;
constexpr Cmd cmdGetThermalLimit = 0x0C;
constexpr Cmd cmdGetTemperatureReadings = 0x10;
constexpr Cmd cmdSetDcmiConfigParameters = 0x12;
constexpr Cmd cmdGetDcmiConfigParameters = 0x13;
} // namespace dcmi

} // namespace ipmi
