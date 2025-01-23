#pragma once

constexpr auto sbmrBootStateService = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrBootStateObj = "/xyz/openbmc_project/state/boot/raw0";
constexpr auto sbmrBootStateIntf = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrHostStateService = "xyz.openbmc_project.State.Host";
constexpr auto sbmrHostStateObject = "/xyz/openbmc_project/state/host0";
constexpr auto sbmrHostStateInf = "xyz.openbmc_project.State.Boot.Progress";
constexpr auto sbmrBootProgressCodeSize = 9;
constexpr auto oemSbmrBootStage = "OEM";
constexpr auto dbusPropertyInterface = "org.freedesktop.DBus.Properties";
