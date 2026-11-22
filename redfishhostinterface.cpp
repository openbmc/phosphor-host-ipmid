/*
 * Copyright (c) 2025 Ampere Computing LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <bootstrap_credentials.hpp>
#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <user_channel/user_layer.hpp>
#include <user_channel/user_mgmt.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <expected>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace phosphor::logging;

using NoResource =
    sdbusplus::error::xyz::openbmc_project::user::common::NoResource;

static constexpr const char* credBootstrappingInf =
    "xyz.openbmc_project.HostInterface.CredentialBootstrapping";
static constexpr const char* credBootstrapEnabledProp =
    "CredentialBootstrappingEnabled";
static constexpr const char* credBootstrapRoleIdProp =
    "CredentialBootstrappingRole";

static std::unordered_map<std::string, CommandPrivilege> credentialRoleIdToUserPriv =
    {{"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.Administrator",
      CommandPrivilege::PRIVILEGE_ADMIN},
     {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.Operator",
      CommandPrivilege::PRIVILEGE_OPERATOR},
     {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.ReadOnly",
      CommandPrivilege::PRIVILEGE_USER}};

namespace ipmi
{

/* Bootstrap account settings */
static constexpr const char* redfishGrpName = "redfish";
static constexpr const char* bootStrapAccountProperty = "BootStrapAccount";

/* DSP0270 8.1.2: the user name and password fields are 16 bytes each */
constexpr uint8_t bootstrapUserNameSize = 16;
constexpr uint8_t bootstrapPasswordSize = 16;

/* Credential bootstrapping control option */
constexpr uint8_t keepCredBootstrapEnabled = 0xa5;

namespace bootStrap
{
constexpr Cmd cmdGetMngCertFingerprint = 0x01;
constexpr Cmd cmdGetBootstrapAccountCred = 0x02;
} // namespace bootStrap

/* helper functions for the various bootStrap command error response types */
static inline auto responseCmdDisabled()
{
    constexpr Cc ccCredsBootstrapDisabled = 0x80;
    return response(ccCredsBootstrapDisabled);
}

static inline auto responseCertsNumberInvalid()
{
    constexpr Cc ccCertificateNumberInvalid = 0xCB;
    return response(ccCertificateNumberInvalid);
}

/* Attempts at a password PAM accepts for a bootstrap account */
static constexpr uint8_t maxBootstrapPasswordRetry = 5;

} // namespace ipmi

/* The Redfish host interface is a host-local channel. Any medium the host
 * itself drives (KCS/BT via the system interface, SMBus/SSIF, USB, ...) is
 * acceptable; network-based media are not, since the bootstrap credentials
 * must not be obtainable from off-platform. */
bool checkRHIAllowedMediumType(const uint8_t& mediumType)
{
    switch (static_cast<ipmi::EChannelMediumType>(mediumType))
    {
        case ipmi::EChannelMediumType::lan8032:
        case ipmi::EChannelMediumType::otherLan:
        case ipmi::EChannelMediumType::serial:
            return false;
        default:
            return true;
    }
}

std::shared_ptr<X509> loadCert(const std::string& filePath)
{
    std::shared_ptr<BIO> certFileBio{BIO_new_file(filePath.c_str(), "rb"),
                                     BIO_free};
    if (certFileBio == nullptr)
    {
        lg2::error("Error occurred during BIO_new_file call, path {PATH}",
                   "PATH", filePath);
        return nullptr;
    }

    X509* cert = nullptr;
    if (PEM_read_bio_X509(certFileBio.get(), &cert, nullptr, nullptr) ==
        nullptr)
    {
        lg2::error("Error occurred during PEM_read_bio_X509 call, path {PATH}",
                   "PATH", filePath);
        return nullptr;
    }

    return std::shared_ptr<X509>(cert, X509_free);
}

/** @brief implements the get CredentialBootstrapping's Enabled property
 *
 *  @returns 1 - enabled, 0 - disabled, std::nullopt if error
 */
std::optional<bool> getCredentialBootstrapEnabledProperty(
    ipmi::Context::ptr ctx)
{
    boost::system::error_code ec;
    bool enabled = false;

    ec = ipmi::getDbusProperty<bool>(
        ctx, ipmi::userMgrService, ipmi::userObjBasePath, credBootstrappingInf,
        credBootstrapEnabledProp, enabled);
    if (ec)
    {
        lg2::error("Failed to get CredentialBootstrap property {STATUS}",
                   "STATUS", ec.what());
        return std::nullopt;
    }

    return enabled;
}

/** @brief implements the Get manager certificate fingerprint command
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] certNum - Certificate number
 *
 *  @returns IPMI completion code plus response data for
 *   - the Get manager certificate fingerprint command
 */
ipmi::RspType<uint8_t,              // hash type
              std::vector<uint8_t>> // hash data
    getFingerprint(ipmi::Context::ptr ctx, uint8_t certNum)
{
    if (certNum != 0x1)
    {
        lg2::error("Invalid certNum {CER}.", "CER", certNum);
        return ipmi::responseCertsNumberInvalid();
    }

    /* Get Enabled property within the CredentialBootstrapping property of the
     * host interface. */
    auto enabledState = getCredentialBootstrapEnabledProperty(ctx);
    if (!enabledState || (*enabledState == false))
    {
        lg2::error("CredentialBootstrapping is disabled.");
        return ipmi::responseCmdDisabled();
    }

    const std::string certFile = "/etc/ssl/certs/https/server.pem";
    auto cert = loadCert(certFile);
    if (cert == nullptr)
    {
        lg2::error("Failed to read cert");
        return ipmi::responseUnspecifiedError();
    }

    std::vector<uint8_t> cnBuffer(EVP_MAX_MD_SIZE);
    unsigned int cnBufferLen = 0;
    if (!X509_digest(cert.get(), EVP_sha256(), cnBuffer.data(), &cnBufferLen))
    {
        lg2::error("Failed to get finger print.");
        return ipmi::responseUnspecifiedError();
    }

    /* 32 bytes of the fingerprint */
    constexpr size_t maxFingerPrintLength = 32;
    if (cnBufferLen != maxFingerPrintLength)
    {
        lg2::error("Failed to get finger print.");
        return ipmi::responseUnspecifiedError();
    }
    cnBuffer.resize(cnBufferLen);

    constexpr uint8_t sha256Type = 0x01;
    return ipmi::responseSuccess(sha256Type, cnBuffer);
}

ipmi::Cc filterRHICommands(ipmi::message::Request::ptr request)
{
    if (request->ctx->netFn != ipmi::netFnGroup ||
        request->ctx->group != ipmi::groupRedfish)
    {
        // Skip if not group SBMR
        return ipmi::ccSuccess;
    }

    ipmi::ChannelInfo chInfo{};
    if (ipmi::getChannelInfo(request->ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info, channel={CHANNEL}", "CHANNEL",
                   request->ctx->channel);
        return ipmi::ccUnspecifiedError;
    }

    if (!checkRHIAllowedMediumType(chInfo.mediumType))
    {
        lg2::error("Error - Medium interface not supported, medium={TYPE}",
                   "TYPE", chInfo.mediumType);
        return ipmi::ccCommandNotAvailable;
    }

    return ipmi::ccSuccess;
}

/** @brief implements the set CredentialBootstrapping's Enabled property
 *
 *  @param[in] ctx - Context pointer
 *  @param[in] pValue - enable status
 *
 *  @returns true when the property was written, false when the write failed
 */
static bool setCredentialBootstrapEnabledProperty(ipmi::Context::ptr ctx,
                                                  const bool& pValue)
{
    boost::system::error_code ec;

    ec = ipmi::setDbusProperty(ctx, ipmi::userMgrService, ipmi::userObjBasePath,
                               credBootstrappingInf, credBootstrapEnabledProp,
                               pValue);

    if (ec)
    {
        lg2::error("Fail to set CredentialBootstrap property {ERROR}", "ERROR",
                   ec.what());
        return false;
    }
    return true;
}

/** @brief implements getting the bootStrapAccount user Privilege base on the
 *         CredentialBootstrapping's roleId property
 *
 *  Fails closed: a role that cannot be read or is not recognised never turns
 *  into a privilege, in particular not into administrator.
 *
 *  @returns bootStrapAccount user privilege, or nullopt when the role could
 *           not be resolved
 */
static std::optional<uint8_t> getRedfishHostInterfacePriv(
    ipmi::Context::ptr ctx)
{
    std::string roleId;
    boost::system::error_code ec;

    ec = ipmi::getDbusProperty<std::string>(
        ctx, ipmi::userMgrService, ipmi::userObjBasePath, credBootstrappingInf,
        credBootstrapRoleIdProp, roleId);
    if (ec)
    {
        lg2::error("Failed to get CredentialBootstrap property {STATUS}",
                   "STATUS", ec.what());
        return std::nullopt;
    }

    auto role = credentialRoleIdToUserPriv.find(roleId);
    if (role == credentialRoleIdToUserPriv.end())
    {
        lg2::error("Unknown CredentialBootstrap role {ROLE}", "ROLE", roleId);
        return std::nullopt;
    }

    return role->second;
}

/** @brief Delete a bootstrap account through phosphor-user-manager
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] userName - bootstrap account user name
 */
static void deleteBootstrapAccount(ipmi::Context::ptr ctx,
                                   const std::string& userName)
{
    sdbusplus::object_path userPath(ipmi::userMgrObjBasePath);
    userPath /= userName;
    boost::system::error_code ec =
        ipmi::callDbusMethod(ctx, ipmi::userMgrService, userPath.str,
                             ipmi::deleteUserInterface, ipmi::deleteUserMethod);
    if (ec)
    {
        lg2::error("Failed to delete bootstrap account {NAME}: {ERROR}", "NAME",
                   userName, "ERROR", ec.message());
    }
}

/** @brief Set a new random password on a bootstrap account
 *
 *  The password is built to meet the policy, but PAM has the final say. A
 *  rejection is worth another random password; any other error would fail
 *  the same way, so it ends the attempts.
 *
 *  @param[in] userName - bootstrap account user name
 *
 *  @returns the password that was set, or nullopt
 */
static std::optional<ipmi::SecureBuffer> setBootstrapPassword(
    const std::string& userName)
{
    for ([[maybe_unused]] auto i :
         std::views::iota(0, static_cast<int>(ipmi::maxBootstrapPasswordRetry)))
    {
        auto password =
            bootstrap_credentials::createPassword(ipmi::bootstrapPasswordSize);
        if (!password)
        {
            lg2::error("Failed to create password for bootstrap account.");
            return std::nullopt;
        }
        auto rc = ipmi::ipmiSetSpecialUserPassword(
            userName, ipmi::SecureString(password->begin(), password->end()));
        if (rc == ipmi::ccSuccess)
        {
            return password;
        }
        if (rc != ipmi::ccInvalidFieldRequest)
        {
            lg2::error("Failed to set password of bootstrap account {NAME}",
                       "NAME", userName);
            return std::nullopt;
        }
        lg2::info("Bootstrap password was rejected, trying another one.");
    }

    lg2::error("Every password for bootstrap account {NAME} was rejected",
               "NAME", userName);
    return std::nullopt;
}

/** @brief Ask phosphor-user-manager to create the bootstrap account
 *
 *  Reads the reply message instead of using ipmi::callDbusMethod, whose
 *  error code keeps only the errno. Every user-manager error arrives as EIO,
 *  so only the D-Bus error name tells "no room for another account" apart.
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] userName - bootstrap account user name
 *  @param[in] priv - user-manager privilege for the account
 *
 *  @returns ccSuccess, ccOutOfSpace when user-manager has no room for another
 *           non-IPMI account, ccUnspecifiedError for any other failure
 */
static ipmi::Cc createUserAccount(ipmi::Context::ptr ctx,
                                  const std::string& userName,
                                  const std::string& priv)
{
    std::vector<std::string> groups = {
        static_cast<std::string>(ipmi::redfishGrpName)};
    boost::system::error_code ec;
    sdbusplus::message_t reply;
    try
    {
        auto method = ctx->bus->new_method_call(
            ipmi::userMgrService, ipmi::userMgrObjBasePath,
            ipmi::userMgrInterface, ipmi::createUserMethod);
        method.append(userName, groups, priv, true);
        reply = ctx->bus->async_send_yield(method, ctx->yield[ec]);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to create bootstrap account {NAME}: {ERROR}", "NAME",
                   userName, "ERROR", e);
        return ipmi::ccUnspecifiedError;
    }
    if (!ec)
    {
        return ipmi::ccSuccess;
    }

    /* No error is attached when the call could not be sent at all */
    const sd_bus_error* error = reply.get_error();
    std::string_view errName =
        (error != nullptr && error->name != nullptr) ? error->name : "";
    lg2::error(
        "Failed to create bootstrap account {NAME}: {ERROR} {DBUS_ERROR}",
        "NAME", userName, "ERROR", ec.message(), "DBUS_ERROR", errName);
    if (errName == NoResource::errName)
    {
        return ipmi::ccOutOfSpace;
    }
    return ipmi::ccUnspecifiedError;
}

/** @brief Create the bootstrap account through phosphor-user-manager
 *
 *  The account is a Redfish-only account. It is created by name and is not
 *  placed in the IPMI user table, so it does not use an IPMI user ID. The
 *  D-Bus calls yield, so ipmid keeps serving other requests meanwhile.
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] userName - bootstrap account user name
 *  @param[in] priv - user-manager privilege for the account
 *
 *  @returns the account's password when the account is
 *           fully created, otherwise the completion code to return (nothing
 *           is left behind)
 */
static std::expected<ipmi::SecureBuffer, ipmi::Cc> createBootstrapAccount(
    ipmi::Context::ptr ctx, const std::string& userName,
    const std::string& priv)
{
    auto cc = createUserAccount(ctx, userName, priv);
    if (cc != ipmi::ccSuccess)
    {
        return std::unexpected(cc);
    }

    auto password = setBootstrapPassword(userName);
    if (!password)
    {
        deleteBootstrapAccount(ctx, userName);
        return std::unexpected(ipmi::ccUnspecifiedError);
    }

    sdbusplus::object_path userPath(ipmi::userMgrObjBasePath);
    userPath /= userName;
    auto ec = ipmi::setDbusProperty(ctx, ipmi::userMgrService, userPath.str,
                                    ipmi::usersInterface,
                                    ipmi::bootStrapAccountProperty, true);
    if (ec)
    {
        lg2::error("Failed to set {PROPERTY} for account {NAME}: {ERROR}",
                   "PROPERTY", ipmi::bootStrapAccountProperty, "NAME", userName,
                   "ERROR", ec.message());
        deleteBootstrapAccount(ctx, userName);
        return std::unexpected(ipmi::ccUnspecifiedError);
    }

    lg2::info("Bootstrap account {NAME} created", "NAME", userName);
    return std::move(*password);
}

/** @brief Lets only one bootstrap request run at a time
 *
 *  Every D-Bus call in the handler yields, so without the gate a second
 *  request can read Enabled while the first one is still creating its
 *  account, and both get one even though the first disables bootstrapping.
 *  ipmid runs handlers as coroutines on one thread, so a flag is enough.
 */
class BootstrapRequestGate
{
  public:
    BootstrapRequestGate() : acquired(!std::exchange(active, true)) {}
    BootstrapRequestGate(const BootstrapRequestGate&) = delete;
    BootstrapRequestGate& operator=(const BootstrapRequestGate&) = delete;

    ~BootstrapRequestGate()
    {
        if (acquired)
        {
            active = false;
        }
    }

    explicit operator bool() const
    {
        return acquired;
    }

  private:
    static inline bool active = false;
    bool acquired;
};

/** @brief Implements the Get bootstrap account credentials command
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] bootstrapControl - Disable credential bootstrapping control
 *
 *  @returns IPMI completion code plus response data for
 *   - the Get bootstrap account credentials command
 */
static ipmi::RspType<ipmi::SecureBuffer, /* 16 bytes user name */
                     ipmi::SecureBuffer> /* 16 bytes user password */
    getBootstrapAccountCredentials(ipmi::Context::ptr ctx,
                                   uint8_t bootstrapControl)
{
    BootstrapRequestGate gate;
    if (!gate)
    {
        lg2::info("Bootstrap credentials request already in progress.");
        return ipmi::responseBusy();
    }

    /* Get Enabled property within the CredentialBootstrapping property of the
     * host interface. */
    auto enabledState = getCredentialBootstrapEnabledProperty(ctx);
    if (!enabledState || (*enabledState == false))
    {
        lg2::error("CredentialBootstrapping is disabled.");
        return ipmi::responseCmdDisabled();
    }

    auto bootStrapRole = getRedfishHostInterfacePriv(ctx);
    if (!bootStrapRole)
    {
        lg2::error("Failed to resolve the bootstrap account role.");
        return ipmi::responseUnspecifiedError();
    }
    std::string bootStrapPriv = ipmi::UserAccess::convertToSystemPrivilege(
        static_cast<CommandPrivilege>(*bootStrapRole));

    auto userName =
        bootstrap_credentials::createUserName(ipmi::bootstrapUserNameSize);
    if (!userName)
    {
        lg2::error("Failed to create BootStrap userName.");
        return ipmi::responseUnspecifiedError();
    }

    const std::string userNameStr(userName->begin(), userName->end());
    auto password = createBootstrapAccount(ctx, userNameStr, bootStrapPriv);
    if (!password)
    {
        return ipmi::response(password.error());
    }

    if (bootstrapControl != ipmi::keepCredBootstrapEnabled)
    {
        lg2::info("Set CredentialBootstrapping to disabled");
        if (!setCredentialBootstrapEnabledProperty(ctx, false))
        {
            /* Bootstrapping stays enabled, so the host must not be told it
             * succeeded, and the account it never receives must not stay */
            deleteBootstrapAccount(ctx, userNameStr);
            return ipmi::responseUnspecifiedError();
        }
    }
    else
    {
        lg2::info("Keep credential bootstrapping enabled");
    }

    /*
     * As DSP0270 8.1.2, bytes[3:18] are the user name and bytes[19:34] the
     * password, each a FIXED 16 byte field. The name and password generation
     * code ensures correct lengths, so no padding is needed.
     */
    return ipmi::responseSuccess(*userName, *password);
}

void registerNetfnRedfishHostInterfaceFunctions() __attribute__((constructor));
void registerNetfnRedfishHostInterfaceFunctions()
{
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupRedfish,
                               ipmi::bootStrap::cmdGetMngCertFingerprint,
                               ipmi::Privilege::User, getFingerprint);
    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, ipmi::groupRedfish,
        ipmi::bootStrap::cmdGetBootstrapAccountCred, ipmi::Privilege::User,
        getBootstrapAccountCredentials);
    ipmi::registerFilter(ipmi::prioOpenBmcBase,
                         [](ipmi::message::Request::ptr request) {
                             return filterRHICommands(request);
                         });
}
