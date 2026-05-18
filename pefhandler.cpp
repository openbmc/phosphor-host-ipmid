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
 * All D-Bus traffic uses the yielding (coroutine) sdbusplus API on
 * the per-request ipmi::Context, so the ipmid main loop is never
 * blocked on a slow or stuck provider -- other IPMI traffic continues
 * to interleave, and the handler can safely call into daemons that
 * may, transitively, dispatch back through ipmid.
 *
 * SetInProgress (param 0x00) is stored as a process-local, transient
 * flag. Per IPMI 2.0 sec 30.3 a fully compliant implementation should
 * reject parameter writes from other principals with completion code
 * 0x81 ("Set in progress") while the flag is set by another session.
 * We do NOT enforce that today: parameter writes proceed regardless of
 * the flag value. This is acceptable because the BMC has a single
 * authoritative writer in practice; revisit if multiple management
 * controllers begin sharing PEF configuration.
 */

#include "pefhandler.hpp"

#include <ipmid/api.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/handler.hpp>
#include <ipmid/message.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/exception.hpp>

#include <boost/system/error_code.hpp>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

using namespace phosphor::logging;

// ---------------------------------------------------------------------------
// Local constants
// ---------------------------------------------------------------------------
constexpr uint8_t pefVersion = 0x51;

#ifndef PEF_ACTION_SUPPORT
#define PEF_ACTION_SUPPORT 0x10
#endif
constexpr uint8_t pefActionSupport = PEF_ACTION_SUPPORT;
constexpr uint8_t maxAlertPolicies = 0;
constexpr uint8_t pefParamRev = 0x11;

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

// ---------------------------------------------------------------------------
// D-Bus call result
// ---------------------------------------------------------------------------
enum class DbusResult
{
    Ok,
    NoService,
    Error,
};

// ---------------------------------------------------------------------------
// Process-local state
// ---------------------------------------------------------------------------
std::mutex pefMutex;
uint8_t setInProgress = 0;

std::string& serviceCache()
{
    static std::string cache;
    return cache;
}

void invalidateService()
{
    serviceCache().clear();
}

// Classify a coroutine-yielded error_code. We can't recover the
// org.freedesktop.DBus.Error.* name from an error_code, so we
// conservatively treat a small set of "host unreachable" style codes
// as NoService and everything else as a generic Error. resolveService
// still goes through the exception path and gets the precise mapping.
DbusResult classifyEc(const boost::system::error_code& ec)
{
    namespace errc = boost::system::errc;
    if (ec == errc::host_unreachable || ec == errc::no_such_process ||
        ec == errc::connection_refused || ec == errc::timed_out ||
        ec == errc::not_connected || ec == errc::no_such_file_or_directory ||
        ec == errc::address_not_available)
    {
        return DbusResult::NoService;
    }
    // sd-bus surfaces ServiceUnknown / NameHasNoOwner / NoReply /
    // Disconnected as generic boost error_codes whose message text
    // carries the underlying D-Bus error name. Inspect the message
    // so the Set path can report Destination Unavailable (CC 0xD3)
    // when the provider's bus name has no owner, instead of falling
    // back to Unspecified Error (CC 0xFF).
    const std::string m = ec.message();
    if (m.find("ServiceUnknown") != std::string::npos ||
        m.find("NameHasNoOwner") != std::string::npos ||
        m.find("not activatable") != std::string::npos ||
        m.find("NoReply") != std::string::npos ||
        m.find("Disconnected") != std::string::npos ||
        m.find("NoServer") != std::string::npos)
    {
        return DbusResult::NoService;
    }
    return DbusResult::Error;
}

// ---------------------------------------------------------------------------
// D-Bus helpers (all yielding)
// ---------------------------------------------------------------------------
DbusResult resolveService(ipmi::Context::ptr ctx, std::string& outSvc)
{
    auto& cache = serviceCache();
    if (!cache.empty())
    {
        outSvc = cache;
        return DbusResult::Ok;
    }
    std::string svc;
    boost::system::error_code ec = ipmi::getService(
        ctx, std::string(pef::pefMgrIntf), std::string(pef::pefMgrPath), svc);
    if (ec)
    {
        log<level::ERR>("PEF: ObjectMapper lookup failed",
                        entry("ERR=%s", ec.message().c_str()));
        cache.clear();
        // A failed ObjectMapper lookup means no daemon currently owns the
        // PefManager interface on the bus; surface that as Destination
        // Unavailable (CC 0xD3) rather than the catch-all Unspecified
        // Error, regardless of which posix code sd-bus translated to.
        return DbusResult::NoService;
    }
    cache = svc;
    outSvc = svc;
    return DbusResult::Ok;
}

DbusResult dbusGetByteProp(ipmi::Context::ptr ctx, const char* prop,
                           uint8_t& out)
{
    std::string svc;
    if (auto r = resolveService(ctx, svc); r != DbusResult::Ok)
    {
        return r;
    }
    boost::system::error_code ec;
    auto v = ctx->bus->yield_method_call<std::variant<uint8_t>>(
        ctx->yield, ec, svc, pef::pefMgrPath, pef::dbusPropsIntf, "Get",
        std::string(pef::pefMgrIntf), std::string(prop));
    if (ec)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus Get property failed",
                        entry("PROP=%s", prop),
                        entry("ERR=%s", ec.message().c_str()));
        return classifyEc(ec);
    }
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

DbusResult dbusSetByteProp(ipmi::Context::ptr ctx, const char* prop,
                           uint8_t val)
{
    std::string svc;
    if (auto r = resolveService(ctx, svc); r != DbusResult::Ok)
    {
        return r;
    }
    boost::system::error_code ec;
    ctx->bus->yield_method_call<void>(
        ctx->yield, ec, svc, pef::pefMgrPath, pef::dbusPropsIntf, "Set",
        std::string(pef::pefMgrIntf), std::string(prop),
        std::variant<uint8_t>(val));
    if (ec)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus Set property failed",
                        entry("PROP=%s", prop),
                        entry("ERR=%s", ec.message().c_str()));
        return classifyEc(ec);
    }
    return DbusResult::Ok;
}

DbusResult dbusSetFilter(ipmi::Context::ptr ctx, uint8_t num,
                         const uint8_t* raw)
{
    std::string svc;
    if (auto r = resolveService(ctx, svc); r != DbusResult::Ok)
    {
        return r;
    }
    boost::system::error_code ec;
    std::vector<uint8_t> v(raw, raw + pef::pefEntryBytes);
    ctx->bus->yield_method_call<void>(
        ctx->yield, ec, svc, pef::pefMgrPath, pef::pefMgrIntf,
        pef::methodSetFilter, num, v);
    if (ec)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus SetFilter failed",
                        entry("ERR=%s", ec.message().c_str()));
        return classifyEc(ec);
    }
    return DbusResult::Ok;
}

DbusResult dbusGetFilter(ipmi::Context::ptr ctx, uint8_t num, uint8_t* raw)
{
    std::memset(raw, 0, pef::pefEntryBytes);
    std::string svc;
    if (auto r = resolveService(ctx, svc); r != DbusResult::Ok)
    {
        return r;
    }
    boost::system::error_code ec;
    auto v = ctx->bus->yield_method_call<std::vector<uint8_t>>(
        ctx->yield, ec, svc, pef::pefMgrPath, pef::pefMgrIntf,
        pef::methodGetFilter, num);
    if (ec)
    {
        invalidateService();
        log<level::ERR>("PEF: D-Bus GetFilter failed",
                        entry("ERR=%s", ec.message().c_str()));
        return classifyEc(ec);
    }
    if (v.size() != pef::pefEntryBytes)
    {
        log<level::ERR>("PEF: GetFilter returned wrong size");
        return DbusResult::Error;
    }
    std::memcpy(raw, v.data(), pef::pefEntryBytes);
    return DbusResult::Ok;
}

// Set-path: map DbusResult to a completion-code response.
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
    // Defensive: an unexpected DbusResult value reaches the IPMI client as a
    // generic error rather than aborting the handler thread.
    return ipmi::responseUnspecifiedError();
}

// Get-path: nullopt on Ok (caller packs payload); fully-formed error
// response on NoService/Error.
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
    return ipmi::responseUnspecifiedError();
}

// ---------------------------------------------------------------------------
// Cmd 0x10: Get PEF Capabilities  (no D-Bus; no ctx needed)
// ---------------------------------------------------------------------------
ipmi::RspType<uint8_t, uint8_t, uint8_t> ipmiGetPefCapabilities()
{
    return ipmi::responseSuccess(pefVersion, pefActionSupport,
                                 pef::pefMaxFilters);
}

// ---------------------------------------------------------------------------
// Cmd 0x12: Set PEF Configuration Parameters
// ---------------------------------------------------------------------------
ipmi::RspType<> ipmiSetPefConfigParams(ipmi::Context::ptr ctx,
                                       uint8_t paramSelByte,
                                       ipmi::message::Payload& req)
{
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
            return ccFor(dbusSetByteProp(ctx, pef::propControl, v & 0x01));
        }

        case PefParam::PefActionGlobalCtrl:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((v & ~pefActionSupport) != 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            return ccFor(dbusSetByteProp(ctx, pef::propActionGlobalCtrl, v));
        }

        case PefParam::PefStartupDelay:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            return ccFor(dbusSetByteProp(ctx, pef::propStartupDelay, v));
        }

        case PefParam::PefAlertStartupDelay:
        {
            uint8_t v = 0;
            if (req.unpack(v) != 0 || !req.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            return ccFor(dbusSetByteProp(ctx, pef::propAlertStartupDelay, v));
        }

        case PefParam::EventFilterTable:
        {
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
            return ccFor(dbusSetFilter(ctx, filterNum, entry.data()));
        }

        case PefParam::EventFilterData1:
        {
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
            switch (dbusGetFilter(ctx, filterNum, raw))
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
            raw[0] = configByte;
            return ccFor(dbusSetFilter(ctx, filterNum, raw));
        }

        default:
            return ipmi::responseParmOutOfRange();
    }
}

// ---------------------------------------------------------------------------
// Cmd 0x13: Get PEF Configuration Parameters
// ---------------------------------------------------------------------------
ipmi::RspType<ipmi::message::Payload> ipmiGetPefConfigParams(
    ipmi::Context::ptr ctx, uint8_t paramSelByte, uint8_t setSelector,
    [[maybe_unused]] uint8_t blockSelector)
{
    uint8_t paramSel = paramSelByte & 0x7F;
    bool getRevisionOnly = (paramSelByte & 0x80) != 0;

    ipmi::message::Payload ret;
    ret.pack(pefParamRev);

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
            if (auto r = mapErr(dbusGetByteProp(ctx, pef::propControl, v)))
            {
                return *r;
            }
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefActionGlobalCtrl:
            if (auto r =
                    mapErr(dbusGetByteProp(ctx, pef::propActionGlobalCtrl, v)))
            {
                return *r;
            }
            v &= pefActionSupport;
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefStartupDelay:
            if (auto r =
                    mapErr(dbusGetByteProp(ctx, pef::propStartupDelay, v)))
            {
                return *r;
            }
            ret.pack(v);
            return ipmi::responseSuccess(std::move(ret));

        case PefParam::PefAlertStartupDelay:
            if (auto r = mapErr(
                    dbusGetByteProp(ctx, pef::propAlertStartupDelay, v)))
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
            if (auto r = mapErr(dbusGetFilter(ctx, filterNum, raw)))
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
            uint8_t filterNum = setSelector;
            if (filterNum == 0 || filterNum > pef::pefMaxFilters)
            {
                return ipmi::responseParmOutOfRange();
            }
            uint8_t raw[pef::pefEntryBytes]{};
            if (auto r = mapErr(dbusGetFilter(ctx, filterNum, raw)))
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
}
