#pragma once

#include <cstdint>

/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 *
 * IPMI 2.0 Platform Event Filtering (PEF) -- D-Bus contract consumed by
 * the IPMI translator in pefhandler.cpp.
 *
 * This header is the canonical declaration of every name and constant
 * the translator uses on the bus. It is intentionally provider-agnostic:
 *
 *   - The owning service name is NOT hardcoded. It is discovered at
 *     runtime via the object mapper. Any daemon that exposes the
 *     interfaces below at the documented paths will satisfy the
 *     contract.
 *
 *   - The translator implements three IPMI commands (NetFn 0x04 Sensor):
 *       Cmd 0x10  Get PEF Capabilities
 *       Cmd 0x12  Set PEF Configuration Parameters
 *       Cmd 0x13  Get PEF Configuration Parameters
 *
 * D-Bus contract
 * --------------
 *
 * Manager object
 *   path : /xyz/openbmc_project/inventory/pef
 *   iface: xyz.openbmc_project.PefManager
 *
 *   properties (all uint8, read/write unless noted):
 *     Control            -- IPMI 2.0 PEF Control bitmask:
 *                             bit 0 PEF enable
 *                             bit 1 event-message-action enable
 *                             bit 2 startup-delay enable
 *                             bit 3 alert-startup-delay enable
 *     ActionGlobalCtrl   -- IPMI 2.0 PEF Action Global Control bitmask
 *     StartupDelay       -- seconds
 *     AlertStartupDelay  -- seconds
 *
 *   The filter table is fixed at pefMaxFilters (40) slots; both
 *   the translator and the matcher rely on this constant. The
 *   provider must expose exactly pefMaxFilters slots numbered
 *   1..pefMaxFilters.
 *
 *   methods:
 *     SetFilter(uint8 num, array<byte,20> raw)
 *     GetFilter(uint8 num) -> array<byte,20>
 *
 *     `num` is 1-based and must be in [1, MaxFilters]. `raw` is the full
 *     20-byte filter entry as defined by IPMI 2.0 Table 17.7 (Event
 *     Filter Table Entry).
 *
 *   The provider MUST host an org.freedesktop.DBus.ObjectManager at
 *   or above /xyz/openbmc_project/inventory/pef. The matcher in
 *   phosphor-sel-logger subscribes InterfacesAdded/Removed against
 *   that path; without an ObjectManager rooted at or above it, slot
 *   add/remove signals never arrive and the matcher relies solely on
 *   the initial cache prime + PropertiesChanged.
 *
 * Per-filter object (one per slot, present only for populated slots)
 *   path : /xyz/openbmc_project/inventory/pef/Filter<N>   (N = 1..MaxFilters)
 *   iface: xyz.openbmc_project.PefFilter
 *
 *   property:
 *     RawData : array<byte,20>   -- same 20-byte layout as above
 *
 * Byte layout reference (IPMI 2.0 Table 17.7) for the 20-byte entry:
 *   [0]  Filter Configuration   (bit 7 = enable)
 *   [1]  Filter Action          (bit 4 = OEM action)
 *   [2]  Alert Policy Number
 *   [3]  Event Severity
 *   [4]  Generator ID byte 1    (slave/SW addr; 0xFF = match any)
 *   [5]  Generator ID byte 2    (channel# | LUN)
 *   [6]  Sensor Type            (0xFF = match any)
 *   [7]  Sensor Number          (0xFF = match any)
 *   [8]  Event Trigger          (event/reading type; 0xFF = match any)
 *   [9]  Event Data 1 AND mask
 *   [10] Event Data 1 Compare 1
 *   [11] Event Data 1 Compare 2
 *   [12] Event Data 2 AND mask
 *   [13] Event Data 2 Compare 1
 *   [14] Event Data 2 Compare 2
 *   [15] Event Data 3 AND mask
 *   [16] Event Data 3 Compare 1
 *   [17] Event Data 3 Compare 2
 *   [18] Alert String Set / Selector  (unused today)
 *   [19] Group Control Selector       (unused today)
 *
 * The translator returns the standard IPMI completion codes;
 * D-Bus errors from the manager surface as 0xD3 (Destination
 * Unavailable) when the provider is absent and 0xFF (Unspecified)
 * for any other failure.
 */

namespace pef
{

inline constexpr uint8_t pefEntryBytes = 20;
inline constexpr uint8_t pefMaxFilters = 40;
inline constexpr uint8_t pefOemActionBit = 0x10;
inline constexpr uint8_t pefEnableBit = 0x80;

// IPMI 2.0 sec 17.7 Table 17.7, Filter Action byte (entry byte 1),
// bit 4 = OEM action. The spec is the single source of truth; the
// matcher in phosphor-sel-logger carries an identical assert so
// either side typo'ing the value fails to compile.
static_assert(pefOemActionBit == (1u << 4),
              "IPMI 2.0 sec 17.7 Filter Action bit 4 = OEM action");

inline constexpr const char* pefMgrPath =
    "/xyz/openbmc_project/inventory/pef";
inline constexpr const char* pefMgrIntf = "xyz.openbmc_project.PefManager";
inline constexpr const char* pefFilterIntf = "xyz.openbmc_project.PefFilter";

// Manager interface property names
inline constexpr const char* propControl = "Control";
inline constexpr const char* propActionGlobalCtrl = "ActionGlobalCtrl";
inline constexpr const char* propStartupDelay = "StartupDelay";
inline constexpr const char* propAlertStartupDelay = "AlertStartupDelay";

// Manager interface method names
inline constexpr const char* methodSetFilter = "SetFilter";
inline constexpr const char* methodGetFilter = "GetFilter";

// Per-filter interface property name
inline constexpr const char* propRawData = "RawData";

inline constexpr const char* dbusPropsIntf =
    "org.freedesktop.DBus.Properties";

} // namespace pef
