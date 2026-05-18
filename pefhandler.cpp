/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 *
 * IPMI 2.0 Platform Event Filtering (PEF) translator.
 *
 * Implements the following NetFn 0x04 (Sensor/Event) commands:
 *   Cmd 0x10  Get PEF Capabilities
 *   Cmd 0x12  Set PEF Configuration Parameters
 *   Cmd 0x13  Get PEF Configuration Parameters
 *
 * Each command is translated into D-Bus calls against the contract
 * documented in pefhandler.hpp. The owning service name is discovered
 * at runtime via the object mapper, so this translator is independent
 * of any particular provider implementation: any daemon that exposes
 * xyz.openbmc_project.PefManager at the documented path satisfies the
 * contract.
 *
 * SetInProgress (param 0x00) is stored as a process-local, transient
 * flag. Per IPMI 2.0 sec 30.3 a fully compliant implementation should
 * reject parameter writes from other principals with completion code
 * 0x81 ("Set in progress") while the flag is set by another session.
 * We do NOT enforce that today: parameter writes proceed regardless of
 * the flag value. This is acceptable because the BMC has a single
 * authoritative writer in practice; revisit if multiple management
 * controllers begin sharing PEF configuration.
 *
 * All D-Bus calls use a bounded timeout so the ipmid main loop never
 * stalls long enough to trip the host IPMI watchdog if the provider is
 * slow, restarting, or wedged.
 */

#include "pefhandler.hpp"

#include <ipmid/api.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/handler.hpp>
#include <ipmid/message.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

// Contain the using-directive to this TU's anonymous namespace so it
// does not leak into the wider phosphor-host-ipmid translation units.
using namespace phosphor::logging;

// ---------------------------------------------------------------------------
// Local constants
// ---------------------------------------------------------------------------
// PEF version field per IPMI 2.0 sec 30.3 Get PEF Capabilities
// Response: BCD encoded, LSN first; 0x51 decodes to v1.5
// (low nibble "1" then high nibble "5"). Do NOT "correct"
// this to 0x15 -- the byte order is spec-defined.
constexpr uint8_t pefVersion = 0x51;
// IPMI 2.0 sec 30.1 Table 30-2, Get PEF Capabilities response
// byte 3 - Action Support. This byte is the BMC's truthful
// self-description on the wire and must list only actions that
// are actually delivered end-to-end on this build.
//
//   bit | hex  | action
//   ----+------+----------------------------------------
//    0  | 0x01 | Alert
//    1  | 0x02 | Power Down
//    2  | 0x04 | Reset
//    3  | 0x08 | Power Cycle
//    4  | 0x10 | OEM Action
//    5  | 0x20 | Diagnostic Interrupt
//    6  |  -   | reserved
//    7  | 0x80 | OEM Event Record Filtering supported
//
// Default below is the minimal honest contract: OEM Action only
// (bit 4, 0x10), because that is the only action the in-tree SEL
// consumer (phosphor-sel-logger pef_filter_match.hpp) services.
//
// Downstream integrators that wire additional actions through
// their own pipeline override PEF_ACTION_SUPPORT at build time
// by OR-ing the bits above (e.g. -DPEF_ACTION_SUPPORT=0x30 to add
// Diagnostic Interrupt on top of OEM Action, or 0x12 to add Power
// Down). They MUST also raise pef::pefActionsImplemented in
// pef_filter_match.hpp to the same value; the static_assert in
// that header fails the build if the advertised manifest includes
// a bit no consumer implements.
//
// NOTE: this byte is DIFFERENT from the per-entry Filter Action
// byte in Table 17-2 (entry byte 2). Bits 0..4 mean the same
// thing in both, but Table 17-2 uses bit 5 for Diagnostic
// Interrupt (NMI) and bit 6 for group control. The matcher reads
// OEM Action from the entry byte at bit 4 (0x10, see
// pef::pefOemActionBit).
#ifndef PEF_ACTION_SUPPORT
#define PEF_ACTION_SUPPORT 0x10
#endif
constexpr uint8_t pefActionSupport = PEF_ACTION_SUPPORT;
constexpr uint8_t maxAlertPolicies = 0;    // not supported
constexpr uint8_t pefParamRev = 0x11;      // PEF parameter revision 1.1

// Bound the D-Bus call latency so the ipmid main loop cannot stall
// indefinitely waiting on a stuck or restarting provider. Microseconds.
constexpr uint64_t pefDbusTimeoutUs =
    std::chrono::microseconds(std::chrono::seconds(1)).count();

// PEF Configuration parameter selectors (IPMI 2.0 Table 30-3)
enum class PefParam : uint8_t
{
    SetInProgress = 0x00,
    PefControl = 0x01,
    PefActionGlobalCtrl = 0x02,
    PefStartupDelay = 0x03,
    PefAlertStartupDelay = 0x04,
    NumEventFilters = 0x05,
    EventFilterTable = 0x06,
    EventFilterData1 = 0x07,
    NumAlertPolicies = 0x08,
    AlertPolicyTable = 0x09,
    SystemGuid = 0x0A,
    NumAlertStrings = 0x0B,
    AlertStringKeys = 0x0C,
    AlertStrings = 0x0D,
};

// IPMI 2.0 NetFn 0x04 (Sensor/Event) command opcodes implemented here
// are the canonical ipmi::sensor_event::cmd* constants from
// include/ipmid/api-types.hpp:
//   cmdGetPefCapabilities         = 0x10
//   cmdSetPefConfigurationParams  = 0x12
//   cmdGetPefConfigurationParams  = 0x13

// ---------------------------------------------------------------------------
// D-Bus call result
//
// Distinguishes "the PefManager service is simply not present on the
// bus" (NoService -> IPMI 0xD3 Destination Unavailable) from "the
// service is present but the call failed" (Error -> IPMI 0xFF
// Unspecified). Without this split, a clean image with no PEF
// provider returns 0xFF, which clients read as "command broken"
// rather than "feature absent".
// ---------------------------------------------------------------------------
enum class DbusResult
{
    Ok,
    NoService,
    Error,
};

// Portable "this point is unreachable" marker. We use it after
// switch statements that cover every enumerator to keep the
// compiler from warning about a missing return. C++23 has
// std::unreachable(); kirkstone is C++20, so wrap the toolchain
// builtin with a documented fallback for portability.
[[noreturn]] inline void pefUnreachable()
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_unreachable();
#else
    std::abort();
#endif
}

// ---------------------------------------------------------------------------
// Process-local state
// ---------------------------------------------------------------------------
std::mutex pefMutex;
uint8_t setInProgress = 0;

// ---------------------------------------------------------------------------
// D-Bus helpers
// ---------------------------------------------------------------------------
sdbusplus::bus::bus& dbusConn()
{
    static auto bus = sdbusplus::bus::new_default_system();
    return bus;
}

std::string& serviceCache()
{
    static std::string cache;
    return cache;
}

// Lazily resolves the PefManager owning service via ObjectMapper and
// caches the result. The cache is invalidated only when a subsequent
// D-Bus call fails (see invalidateService() in the catch blocks).
// If the provider respawns under a new bus name, the next IPMI
// command will spend one bounded timeout discovering the staleness
// and then succeed on the following invocation.
const std::string& resolveService()
{
    auto& cache = serviceCache();
    if (!cache.empty())
    {
        return cache;
    }
    try
    {
        cache = ipmi::getService(dbusConn(), pef::pefMgrIntf, pef::pefMgrPath);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("PEF: ObjectMapper lookup failed",
                        entry("ERR=%s", e.what()));
        cache.clear();
    }
    return cache;
}

void invalidateService()
{
    serviceCache().clear();
}

DbusResult classifyDbusException(const std::exception& e)
{
    const auto* sd = dynamic_cast<const sdbusplus::exception::SdBusError*>(&e);
    if (sd == nullptr)
    {
        return DbusResult::Error;
    }
    const char* n = sd->name();
    if (n == nullptr)
    {
        return DbusResult::Error;
    }
    const std::string_view name(n);
    if (name == "org.freedesktop.DBus.Error.ServiceUnknown" ||
        name == "org.freedesktop.DBus.Error.NameHasNoOwner" ||
        name == "org.freedesktop.DBus.Error.NoReply" ||
        name == "org.freedesktop.DBus.Error.Disconnected" ||
        name == "org.freedesktop.DBus.Error.NoServer" ||
        name == "org.freedesktop.DBus.Error.TimedOut")
    {
        return DbusResult::NoService;
    }
    return DbusResult::Error;
}

DbusResult dbusGetByteProp(const char* prop, uint8_t& out)
{
    try
    {
        const auto& svc = resolveService();
        if (svc.empty())
        {
            return DbusResult::NoService;
        }
        auto& bus = dbusConn();
        auto m = bus.new_method_call(
            svc.c_str(), pef::pefMgrPath, pef::dbusPropsIntf, "Get");
        m.append(std::string(pef::pefMgrIntf), std::string(prop));
        auto reply = bus.call(m, pefDbusTimeoutUs);
        std::variant<uint8_t> v;
        reply.read(v);
        const auto* parsed = std::get_if<uint8_t>(&v);
        if (parsed == nullptr)
        {
            log<level::ERR>("PEF: D-Bus Get returned wrong type",
                            entry("PROP=%s", prop));
            return DbusResult::Error;
        }
        out = *parsed;
        return DbusResult::Ok;
    }
    catch (const std::exception& e)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus Get property failed",
                        entry("PROP=%s", prop), entry("ERR=%s", e.what()));
        return classifyDbusException(e);
    }
}

// Synchronous Set with reply check so the IPMI completion code reflects
// what actually happened on the bus, not just whether the message was
// queued.
DbusResult dbusSetByteProp(const char* prop, uint8_t val)
{
    try
    {
        const auto& svc = resolveService();
        if (svc.empty())
        {
            return DbusResult::NoService;
        }
        auto& bus = dbusConn();
        auto m = bus.new_method_call(
            svc.c_str(), pef::pefMgrPath, pef::dbusPropsIntf, "Set");
        m.append(std::string(pef::pefMgrIntf), std::string(prop),
                 std::variant<uint8_t>(val));
        // sdbusplus bus.call() throws on a D-Bus error reply, so the
        // catch below covers method-call failures; we only need to
        // discard the empty success reply here.
        (void)bus.call(m, pefDbusTimeoutUs);
        return DbusResult::Ok;
    }
    catch (const std::exception& e)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus Set property failed",
                        entry("PROP=%s", prop), entry("ERR=%s", e.what()));
        return classifyDbusException(e);
    }
}

DbusResult dbusSetFilter(uint8_t num, const uint8_t* raw)
{
    try
    {
        const auto& svc = resolveService();
        if (svc.empty())
        {
            return DbusResult::NoService;
        }
        auto& bus = dbusConn();
        auto m = bus.new_method_call(svc.c_str(), pef::pefMgrPath,
                                     pef::pefMgrIntf, pef::methodSetFilter);
        std::vector<uint8_t> v(raw, raw + pef::pefEntryBytes);
        m.append(num, v);
        (void)bus.call(m, pefDbusTimeoutUs);
        return DbusResult::Ok;
    }
    catch (const std::exception& e)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus SetFilter failed",
                        entry("ERR=%s", e.what()));
        return classifyDbusException(e);
    }
}

DbusResult dbusGetFilter(uint8_t num, uint8_t* raw)
{
    try
    {
        const auto& svc = resolveService();
        if (svc.empty())
        {
            std::memset(raw, 0, pef::pefEntryBytes);
            return DbusResult::NoService;
        }
        auto& bus = dbusConn();
        auto m = bus.new_method_call(svc.c_str(), pef::pefMgrPath,
                                     pef::pefMgrIntf, pef::methodGetFilter);
        m.append(num);
        auto reply = bus.call(m, pefDbusTimeoutUs);
        std::vector<uint8_t> v;
        reply.read(v);
        if (v.size() != pef::pefEntryBytes)
        {
            log<level::ERR>("PEF: GetFilter returned wrong size");
            std::memset(raw, 0, pef::pefEntryBytes);
            return DbusResult::Error;
        }
        std::memcpy(raw, v.data(), pef::pefEntryBytes);
        return DbusResult::Ok;
    }
    catch (const std::exception& e)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus GetFilter failed",
                        entry("ERR=%s", e.what()));
        std::memset(raw, 0, pef::pefEntryBytes);
        return classifyDbusException(e);
    }
}

// Map a DbusResult to the matching IPMI completion code response.
// Set-path only; Get paths cannot use this because they must pack
// a Payload before responseSuccess() and therefore use mapErr<>()
// below. NoService -> 0xD3 Destination Unavailable so a clean
// image with no PEF provider does not look like a broken command.
auto ccFor(DbusResult r)
{
    switch (r)
    {
        case DbusResult::Ok:
            return ipmi::responseSuccess();
        case DbusResult::NoService:
            return ipmi::responseDestinationUnavailable();
        case DbusResult::Error:
            return ipmi::responseUnspecifiedError();
    }
    pefUnreachable();
}

// Get-path equivalent of ccFor: returns nullopt on Ok (caller packs
// the payload and returns success), or a fully-constructed error
// response on NoService/Error. The Resp template parameter lets a
// single helper serve every Get arm regardless of payload type.
using GetRsp = ipmi::RspType<ipmi::message::Payload>;
template <typename Resp = GetRsp>
std::optional<Resp> mapErr(DbusResult r)
{
    switch (r)
    {
        case DbusResult::Ok:
            return std::nullopt;
        case DbusResult::NoService:
            return ipmi::responseDestinationUnavailable();
        case DbusResult::Error:
            return ipmi::responseUnspecifiedError();
    }
    pefUnreachable();
}

// ---------------------------------------------------------------------------
// Cmd 0x10: Get PEF Capabilities
//   Response: <PEF version> <action support> <max filters>
// ---------------------------------------------------------------------------
ipmi::RspType<uint8_t, uint8_t, uint8_t> ipmiGetPefCapabilities()
{
    return ipmi::responseSuccess(pefVersion, pefActionSupport,
                                 pef::pefMaxFilters);
}

// ---------------------------------------------------------------------------
// Cmd 0x12: Set PEF Configuration Parameters
// ---------------------------------------------------------------------------
ipmi::RspType<> ipmiSetPefConfigParams(uint8_t paramSelByte,
                                       ipmi::message::Payload& req)
{
    // IPMI 2.0 sec 30.3 / Table 30-4: the parameter selector for Set
    // PEF Configuration Parameters is a defined 8-bit field with no
    // bit-7 control flag (unlike Get sec 30.4, which carves out
    // bit 7 = "get parameter revision only"). A request with bit 7
    // set is therefore reserved/undefined; rejecting it keeps the
    // mapping from request bytes to actions injective and matches
    // the reserved-field validation pattern used elsewhere in this
    // daemon (e.g. ipmiChassisGetSysBootOptions).
    if (paramSelByte & 0x80)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    uint8_t paramSel = paramSelByte;
    std::lock_guard<std::mutex> lock(pefMutex);

    switch (static_cast<PefParam>(paramSel))
    {
        case PefParam::SetInProgress:
        {
            // See top-of-file note: stored process-locally; we do NOT
            // gate concurrent writers with cc 0x81 today.
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            v &= 0x03;
            if (v == 0x03)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            setInProgress = v;
            return ipmi::responseSuccess();
        }

        case PefParam::PefControl:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // IPMI 2.0 PEF Control is a 4-bit mask (bits 0..3). Today
            // only bit 0 (PEF enable) is plumbed end-to-end; the other
            // bits (event-message-action enable, startup-delay enable,
            // alert-startup-delay enable) are intentionally truncated
            // until the provider grows the corresponding behavior.
            return ccFor(dbusSetByteProp(pef::propControl, v & 0x01));
        }

        case PefParam::PefActionGlobalCtrl:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // Reject bits that were not advertised in pefActionSupport
            // (Get PEF Capabilities). Today the translator advertises
            // OEM action only (bit 4, mask 0x10); downstream builds may
            // raise this via -DPEF_ACTION_SUPPORT, see the comment block
            // above the macro definition.
            if ((v & ~pefActionSupport) != 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            return ccFor(dbusSetByteProp(pef::propActionGlobalCtrl, v));
        }

        case PefParam::PefStartupDelay:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            return ccFor(dbusSetByteProp(pef::propStartupDelay, v));
        }

        case PefParam::PefAlertStartupDelay:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            return ccFor(dbusSetByteProp(pef::propAlertStartupDelay, v));
        }

        case PefParam::EventFilterTable:
        {
            // [filter#] [20-byte entry]
            uint8_t filterNum = 0;
            std::array<uint8_t, pef::pefEntryBytes> entry{};
            if (req.unpack(filterNum, entry) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if (filterNum == 0 || filterNum > pef::pefMaxFilters)
            {
                return ipmi::responseParmOutOfRange();
            }
            return ccFor(dbusSetFilter(filterNum, entry.data()));
        }

        case PefParam::EventFilterData1:
        {
            // IPMI 2.0 sec 30.3 Table 30-3 param 0x07: payload is
            // [filter#] [config byte]. Updates entry byte 0
            // (Filter Configuration) only. The D-Bus contract
            // takes a full 20-byte entry, so RMW preserves bytes
            // 1..19; abort if the baseline read fails so a zeroed
            // RMW cannot destroy an existing filter.
            uint8_t filterNum = 0;
            uint8_t configByte = 0;
            if (req.unpack(filterNum, configByte) != 0 ||
                !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if (filterNum == 0 || filterNum > pef::pefMaxFilters)
            {
                return ipmi::responseParmOutOfRange();
            }
            uint8_t raw[pef::pefEntryBytes]{};
            switch (dbusGetFilter(filterNum, raw))
            {
                case DbusResult::Ok:
                    break;
                case DbusResult::NoService:
                    return ipmi::responseDestinationUnavailable();
                case DbusResult::Error:
                    log<level::ERR>(
                        "PEF: refusing partial update; baseline"
                        " read failed",
                        entry("FILTER=%u", filterNum));
                    return ipmi::responseUnspecifiedError();
            }
            raw[0] = configByte; // ONLY byte 0 per IPMI 2.0 sec 30.3
            return ccFor(dbusSetFilter(filterNum, raw));
        }

        default:
            // Unknown parameter selector. We have already returned
            // for every parameter we accept; for everything else we
            // emit ParmOutOfRange. (We do not touch req.trailingOk
            // here -- it is consulted by fullyUnpacked() which only
            // runs before the switch, so setting it now would have
            // no effect.)
            return ipmi::responseParmOutOfRange();
    }
}

// ---------------------------------------------------------------------------
// Cmd 0x13: Get PEF Configuration Parameters
// ---------------------------------------------------------------------------
ipmi::RspType<ipmi::message::Payload> ipmiGetPefConfigParams(
    uint8_t paramSelByte, uint8_t setSelector,
    [[maybe_unused]] uint8_t blockSelector)
{
    uint8_t paramSel = paramSelByte & 0x7F;
    bool getRevisionOnly = (paramSelByte & 0x80) != 0;

    ipmi::message::Payload ret;
    ret.pack(pefParamRev);

    // IPMI 2.0 sec 30.3: validate the parameter selector before
    // honoring the "get parameter revision only" bit so an unknown
    // selector still returns an error CC instead of CC 0x00 with a
    // bare revision byte. We return CC 0xC9 (Parameter Out of Range)
    // for consistency with every other Get/Set Configuration
    // Parameters handler in phosphor-host-ipmid (chassis cfg, BMC
    // global enables, channel cfg, LAN cfg, SoL cfg). The framework
    // exposes a named helper for 0xC9 (responseParmOutOfRange) and
    // none for 0x80; both are generic-additive completion codes per
    // IPMI 2.0 sec 30.3 / 30.4.
    switch (static_cast<PefParam>(paramSel))
    {
        case PefParam::SetInProgress:
        case PefParam::PefControl:
        case PefParam::PefActionGlobalCtrl:
        case PefParam::PefStartupDelay:
        case PefParam::PefAlertStartupDelay:
        case PefParam::NumEventFilters:
        case PefParam::EventFilterTable:
        case PefParam::EventFilterData1:
        case PefParam::NumAlertPolicies:
            break;
        default:
            return ipmi::responseParmOutOfRange();
    }

    if (getRevisionOnly)
    {
        return ipmi::responseSuccess(std::move(ret));
    }

    std::lock_guard<std::mutex> lock(pefMutex);
    uint8_t v = 0;

    switch (static_cast<PefParam>(paramSel))
    {
        case PefParam::SetInProgress:
            ret.pack(setInProgress);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefControl:
            if (auto r = mapErr(dbusGetByteProp(pef::propControl, v)))
            {
                return *r;
            }
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefActionGlobalCtrl:
            if (auto r = mapErr(dbusGetByteProp(pef::propActionGlobalCtrl, v)))
            {
                return *r;
            }
            // Mask to the action bits this build advertises in Get
            // PEF Capabilities so Get/Set stays self-consistent even
            // when the provider stores a wider default.
            v &= pefActionSupport;
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefStartupDelay:
            if (auto r = mapErr(dbusGetByteProp(pef::propStartupDelay, v)))
            {
                return *r;
            }
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefAlertStartupDelay:
            if (auto r = mapErr(dbusGetByteProp(pef::propAlertStartupDelay, v)))
            {
                return *r;
            }
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::NumEventFilters:
            ret.pack(pef::pefMaxFilters);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::EventFilterTable:
        {
            uint8_t filterNum = setSelector;
            if (filterNum == 0 || filterNum > pef::pefMaxFilters)
            {
                return ipmi::responseParmOutOfRange();
            }
            uint8_t raw[pef::pefEntryBytes]{};
            // Refuse to return CC 0x00 with an all-zero payload when
            // the provider call fails: a zero entry is a meaningful
            // "empty filter" value and would mislead clients.
            if (auto r = mapErr(dbusGetFilter(filterNum, raw)))
            {
                return *r;
            }
            ret.pack(filterNum);
            for (uint8_t b = 0; b < pef::pefEntryBytes; ++b)
            {
                ret.pack(raw[b]);
            }
            return ipmi::responseSuccess(std::move(ret));
        }

        case PefParam::EventFilterData1:
        {
            // IPMI 2.0 sec 30.3 Table 30-3 row 7: response payload
            // after the parameter revision byte is exactly
            // [filter#] [config byte]; pack entry byte 0 only.
            uint8_t filterNum = setSelector;
            if (filterNum == 0 || filterNum > pef::pefMaxFilters)
            {
                return ipmi::responseParmOutOfRange();
            }
            uint8_t raw[pef::pefEntryBytes]{};
            if (auto r = mapErr(dbusGetFilter(filterNum, raw)))
            {
                return *r;
            }
            ret.pack(filterNum);
            ret.pack(raw[0]);
            return ipmi::responseSuccess(std::move(ret));
        }

        case PefParam::NumAlertPolicies:
            ret.pack(maxAlertPolicies);
            return ipmi::responseSuccess(std::move(ret));

        default:
            return ipmi::responseParmOutOfRange();
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
void registerPefFunctions() __attribute__((constructor));
void registerPefFunctions()
{
    // Privilege levels per IPMI 2.0 Appendix G, Table G-1
    // ("Command Number Assignments and Privilege Levels"):
    //   0x10 Get PEF Capabilities       -> User
    //   0x12 Set PEF Configuration Params -> Administrator
    //   0x13 Get PEF Configuration Params -> Operator
    // Set is a policy-mutation surface (rewrites the filter table
    // and global controls) and must be Admin-only; Get exposes the
    // full policy and is Operator per spec.
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetPefCapabilities,
                          ipmi::Privilege::User,
                          ipmiGetPefCapabilities);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetPefConfigurationParams,
                          ipmi::Privilege::Admin,
                          ipmiSetPefConfigParams);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetPefConfigurationParams,
                          ipmi::Privilege::Operator,
                          ipmiGetPefConfigParams);
    // No log<>() call here: this function runs as a static-init
    // constructor before main() and before phosphor-logging's
    // journal binding is set up; an INFO line at this point can
    // land in the wrong sink. The registration side-effect above
    // is the visible behavior.
}
