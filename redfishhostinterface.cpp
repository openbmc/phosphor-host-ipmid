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
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <pwd.h>

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <user_channel/user_layer.hpp>
#include <user_channel/user_mgmt.hpp>

#include <cstring>
#include <filesystem>
#include <ranges>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

using namespace phosphor::logging;

static constexpr const char* credBootstrappingInf =
    "xyz.openbmc_project.HostInterface.CredentialBootstrapping";
static constexpr const char* credBootstrapEnabledProp =
    "CredentialBootstrappingEnabled";
static constexpr const char* credBootstrapRoleIdProp =
    "CredentialBootstrappingRole";

std::unordered_map<std::string, CommandPrivilege> credentialRoleIdToUserPriv = {
    {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.Administrator",
     CommandPrivilege::PRIVILEGE_ADMIN},
    {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.Operator",
     CommandPrivilege::PRIVILEGE_OPERATOR},
    {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.ReadOnly",
     CommandPrivilege::PRIVILEGE_USER}};

namespace ipmi
{

/* Credential bootstrapping control option */
constexpr uint8_t keepCredBootstrapEnabled = 0xa5;

namespace bootStrap
{
constexpr Cmd cmdGetMngCertFingerprint = 0x01;
constexpr Cmd cmdGetBootstrapAccoutCre = 0x02;
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

/* Retry in ipmi user actions */
static constexpr uint8_t maxIpmiUserActionRetry = 5;

/* Retry in creating a valid user and password */
static constexpr uint8_t maxCreateRandomPassworkRetry = 10;
static constexpr uint8_t maxCreateRandomUserNameRetry = 10;

static constexpr uint8_t passwordCharacterTypes = 4;
static constexpr uint8_t userNameCharacterTypes = 3;
static constexpr const char* lowCharacters = "abcdefghijklmnopqrstuvwxyz";
static constexpr const char* upCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static constexpr const char* numberCharacters = "0123456789";
static constexpr const char* specialCharacters = "!@#$%^&*";

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

/** @brief View a null terminated ipmi::SecureBuffer as a string
 *
 *  @param[in] buffer - null terminated (or full) character buffer
 *
 *  @returns string view of the characters before the first null
 */
static std::string_view toStringView(const ipmi::SecureBuffer& buffer)
{
    const auto* data = reinterpret_cast<const char*>(buffer.data());
    return {data, strnlen(data, buffer.size())};
}

/** @brief Check whether the user name is valid
 *
 *  @param[in] userName - user name which needs validate.
 *
 *  @returns true when userName is valid, otherwise return false
 */
bool validUserName(std::string_view useName)
{
    std::string_view lowCharacters{ipmi::lowCharacters};
    std::string_view upCharacters{ipmi::upCharacters};
    std::string_view numberCharacters{ipmi::numberCharacters};

    /* User name format [a-zA-Z][a-zA-Z0-9]*, first character must be alpha */
    if (useName.empty() ||
        (lowCharacters.find(useName.front()) == std::string_view::npos &&
         upCharacters.find(useName.front()) == std::string_view::npos))
    {
        return false;
    }

    bool haveUpChar = false;
    bool haveLowChar = false;
    bool haveNumberChar = false;
    for (auto& useNameChar : useName)
    {
        if (lowCharacters.find(useNameChar) != std::string_view::npos)
        {
            haveLowChar = true;
        }
        else if (upCharacters.find(useNameChar) != std::string_view::npos)
        {
            haveUpChar = true;
        }
        else if (numberCharacters.find(useNameChar) != std::string_view::npos)
        {
            haveNumberChar = true;
        }
        else
        {
            return false;
        }
    }

    return haveLowChar && haveUpChar && haveNumberChar;
}

/** @brief Create random BootStrap Account Name
 *
 *  @param[in] userNameLength - user name length
 *
 *  @returns one random BootStrap Account Name
 */
ipmi::SecureBuffer createRandomUserName(const uint8_t& userNamelength)
{
    /*
     * Create random username has 16 characters and follow this policy
     * + Include 16 characters
     * + Must include at least one Low case character
     * + Must include at least one Up case character
     * + Must include at least one number character
     */
    std::string_view lowCharacters{ipmi::lowCharacters};
    std::string_view upCharacters{ipmi::upCharacters};
    std::string_view numberCharacters{ipmi::numberCharacters};
    std::vector<unsigned char> randomCharType(userNamelength);
    std::vector<unsigned char> randomChar(userNamelength);
    ipmi::SecureBuffer userName(userNamelength + 1, 0);

    if (RAND_bytes(randomCharType.data(), userNamelength) != 1)
    {
        lg2::error("Error generating random bytes with OpenSSL.");
        return {};
    }

    if (RAND_bytes(randomChar.data(), userNamelength) != 1)
    {
        // Handle error if RAND_bytes fails
        lg2::error("Error generating random bytes with OpenSSL.");
        return {};
    }

    for (auto i = 0; i < userNamelength; i++)
    {
        /*
         * User name format [a-zA-Z_][a-zA-Z_0-9]*
         * First charracter should be low or up case
         */
        auto type = randomCharType[i] % ipmi::userNameCharacterTypes;
        if (i == 0)
        {
            type = randomCharType[i] % 2;
        }

        switch (type)
        {
            case 0:
                userName[i] =
                    lowCharacters[randomChar[i] % lowCharacters.length()];
                break;
            case 1:
                userName[i] =
                    upCharacters[randomChar[i] % upCharacters.length()];
                break;
            case 2:
                userName[i] =
                    numberCharacters[randomChar[i] % numberCharacters.length()];
                break;
            default:
                break;
        }
    }
    return userName;
}

/** @brief Create BootStrap Account Name
 *
 *  @param[in] userNameLength - user name length
 *
 *  @returns one valid BootStrap Account Name
 */
ipmi::SecureBuffer createUserName(const uint8_t& userNameLength)
{
    for ([[maybe_unused]] auto i : std::views::iota(
             0, static_cast<int>(ipmi::maxCreateRandomUserNameRetry)))
    {
        ipmi::SecureBuffer userName = createRandomUserName(userNameLength);
        if (userName.empty())
        {
            lg2::error("Failed to create BootStrap userName.");
            continue;
        }
        if (validUserName(toStringView(userName)))
        {
            return userName;
        }
    }

    return {};
}

/** @brief Check whether the password follow the common policy
 *
 *  @param[in] password - password.
 *
 *  @returns true when password is valid, otherwise return false
 */
bool validPassword(std::string_view password)
{
    bool haveUpChar = false;
    bool haveLowChar = false;
    bool haveNumberChar = false;
    bool haveSpecialChar = false;
    std::string_view lowCharacters{ipmi::lowCharacters};
    std::string_view upCharacters{ipmi::upCharacters};
    std::string_view numberCharacters{ipmi::numberCharacters};
    std::string_view specialCharacters{ipmi::specialCharacters};

    for (auto& passwordChar : password)
    {
        if (lowCharacters.find(passwordChar) != std::string_view::npos)
        {
            haveLowChar = true;
        }
        else if (upCharacters.find(passwordChar) != std::string_view::npos)
        {
            haveUpChar = true;
        }
        else if (numberCharacters.find(passwordChar) != std::string_view::npos)
        {
            haveNumberChar = true;
        }
        else if (specialCharacters.find(passwordChar) != std::string_view::npos)
        {
            haveSpecialChar = true;
        }
        else
        {
            return false;
        }
    }

    return haveLowChar && haveUpChar && haveNumberChar && haveSpecialChar;
}

/** @brief Create one random user password
 *
 *  @param[in] passwordLength - length of the random password.
 *
 *  @returns one random password
 */
ipmi::SecureBuffer createRandomPassword(const uint8_t& passwordLength)
{
    /*
     * Create random password has 16 characters and follow common policy
     * + Include 16 characters
     * + Must include at least one Low case character
     * + Must include at least one Up case character
     * + Must include at least one number character
     * + Must include at least one special character
     */
    std::string_view lowCharacters{ipmi::lowCharacters};
    std::string_view upCharacters{ipmi::upCharacters};
    std::string_view numberCharacters{ipmi::numberCharacters};
    std::string_view specialCharacters{ipmi::specialCharacters};
    std::vector<unsigned char> randomCharType(passwordLength);
    std::vector<unsigned char> randomChar(passwordLength);
    ipmi::SecureBuffer password(passwordLength + 1, 0);

    if (RAND_bytes(randomCharType.data(), passwordLength) != 1)
    {
        lg2::error("Error generating random bytes with OpenSSL.");
        return {};
    }

    if (RAND_bytes(randomChar.data(), passwordLength) != 1)
    {
        // Handle error if RAND_bytes fails
        lg2::error("Error generating random bytes with OpenSSL.");
        return {};
    }

    for (auto i = 0; i < passwordLength; i++)
    {
        auto type = randomCharType[i] % ipmi::passwordCharacterTypes;
        switch (type)
        {
            case 0:
                password[i] =
                    lowCharacters[randomChar[i] % lowCharacters.length()];
                break;
            case 1:
                password[i] =
                    upCharacters[randomChar[i] % upCharacters.length()];
                break;
            case 2:
                password[i] =
                    numberCharacters[randomChar[i] % numberCharacters.length()];
                break;
            case 3:
                password[i] = specialCharacters[randomChar[i] %
                                                specialCharacters.length()];
                break;
            default:
                break;
        }
    }
    return password;
}

/** @brief Create one valid password
 *
 *  @param[in] passwordLength - length of the valid password.
 *
 *  @returns password
 */
ipmi::SecureBuffer createPassword(const uint8_t& passwordLength)
{
    for ([[maybe_unused]] auto i : std::views::iota(
             0, static_cast<int>(ipmi::maxCreateRandomPassworkRetry)))
    {
        ipmi::SecureBuffer password = createRandomPassword(passwordLength);
        if (password.empty())
        {
            lg2::error("Failed to create password for BootStrap account.");
            continue;
        }
        if (validPassword(toStringView(password)))
        {
            return password;
        }
    }

    return {};
}

/** @brief implements the set CredentialBootstrapping's Enabled property
 *
 *  @param[in] pValue - Context pointer
 *  @param[in] pValue - enable status
 *
 *  @returns none
 */
void setCredentialBootstrapEnabledProperty(ipmi::Context::ptr ctx,
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
    }
}

/** @brief implements getting the bootStrapAccount user Privilege base on the
 *         CredentialBootstrapping's roleId property
 *
 *  @returns bootStrapAccount user previlege, default PRIVILEGE_ADMIN
 */
uint8_t getRedfishHostInterfacePriv(ipmi::Context::ptr ctx)
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
        return PRIVILEGE_ADMIN;
    }

    if (credentialRoleIdToUserPriv.contains(roleId))
    {
        return credentialRoleIdToUserPriv[roleId];
    }

    return PRIVILEGE_ADMIN;
}

/** @brief Implements the Get bootstrap account credentials command
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] bootstrapControl - Disable credential bootstrapping control
 *
 *  @returns IPMI completion code plus response data for
 *   - the Get bootstrap account credentials command
 */
ipmi::RspType<ipmi::SecureBuffer, /* 16 bytes user name */
              ipmi::SecureBuffer> /* 16 bytes user password */
    getBootstrapAccountCredentials(ipmi::Context::ptr ctx,
                                   uint8_t bootstrapControl)
{
    ipmi::ChannelInfo chInfo{};
    ipmi::SecureBuffer userName;
    ipmi::SecureBuffer password;
    uint8_t userId = 1;
    ipmi::UsersTbl* userData;
    uint8_t userCnt = 1; /* One Reserve user account */

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        lg2::error("Failed to get Channel Info, channel={CHANNEL}", "CHANNEL",
                   ctx->channel);
        return ipmi::responseUnspecifiedError();
    }

    if (!checkRHIAllowedMediumType(chInfo.mediumType))
    {
        lg2::error("Error - Medium interface not supported, medium={TYPE}",
                   "TYPE", chInfo.mediumType);
        return ipmi::responseCommandNotAvailable();
    }

    /* Get Enabled property within the CredentialBootstrapping property of the
     * host interface. */
    auto enabledState = getCredentialBootstrapEnabledProperty(ctx);
    if (!enabledState || (*enabledState == false))
    {
        lg2::error("CredentialBootstrapping is disabled.");
        return ipmi::responseCmdDisabled();
    }

    std::string bootStrapPriv = ipmi::UserAccess::convertToSystemPrivilege(
        static_cast<CommandPrivilege>(getRedfishHostInterfacePriv(ctx)));

    /* Find the user ID empty to set the user name */
    userData = ipmi::getUserAccessObject().getUsersTblPtr();
    for (uint8_t usrIndex = 1; usrIndex <= ipmi::ipmiMaxUsers; ++usrIndex)
    {
        if (userData->user[usrIndex].userInSystem)
        {
            userCnt++;
            continue;
        }

        userId = usrIndex;
        break;
    }
    if (userCnt >= ipmi::ipmiMaxUsers)
    {
        lg2::error("Invalid User ID - Out of range");
        return ipmi::responseParmOutOfRange();
    }

    /*
     * As DSP0270:
     * 8.1.2 Get bootstrap account credentials (NetFn 2Ch, Command 02h)
     * The response data bytes[3:18]:
     * "The user name as a UTF-8 string. Strings with fewer than 16 characters
     * are terminated with a null (00h) character and 00h padded to 16 bytes.
     * => User name length without null (00h) is 15 bytes.
     */
    bool bootstrap0InUsed = ipmi::ipmiUserIsbootstrap0InUsed() ||
                            getpwnam(ipmi::firstUserName) != nullptr;
    if (bootstrap0InUsed)
    {
        userName = createUserName(ipmi::ipmiMaxUserName - 1);
    }
    else
    {
        std::string_view firstUserName{ipmi::firstUserName};
        userName = ipmi::SecureBuffer(ipmi::ipmiMaxUserName, 0);
        std::ranges::copy(firstUserName, userName.begin());
    }

    if (userName.empty())
    {
        lg2::error("Failed to create BootStrap userName.");
        return ipmi::responseUnspecifiedError();
    }

    const std::string userNameStr{toStringView(userName)};
    std::vector<std::string> userGroup = {
        static_cast<std::string>(ipmi::redfishGrpName)};
    auto rc = ipmi::ipmiUserCreateUser(userId, userNameStr, userGroup,
                                       bootStrapPriv, true);
    if (rc == ipmi::ccOutOfSpace)
    {
        lg2::error("Non-ipmi User limit reached");
        return ipmi::responseOutOfSpace();
    }
    if (rc != ipmi::ccSuccess)
    {
        lg2::error("Failed to create userName {NAME} error code {ERROR}.",
                   "NAME", userNameStr, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    for ([[maybe_unused]] auto i :
         std::views::iota(0, static_cast<int>(ipmi::maxIpmiUserActionRetry)))
    {
        /*
         * As DSP0270:
         * 8.1.2 Get bootstrap account credentials (NetFn 2Ch, Command 02h)
         * The response data bytes[19:34]:
         * "The password as a UTF-8 string. Strings with fewer than 16
         * characters are terminated with a null (00h) character and 00h padded
         * to 16 bytes.
         * => Password length without null (00h) is 15 bytes.
         */
        password = createPassword(ipmi::maxIpmi15PasswordSize - 1);
        if (password.empty())
        {
            lg2::error("Failed to create password for BootStrap account.");
            continue;
        }
        rc = ipmi::ipmiUserSetUserPassword(
            userId, reinterpret_cast<const char*>(password.data()));
        if (rc == ipmi::ccSuccess)
        {
            break;
        }
    }

    if (!bootstrap0InUsed)
    {
        ipmi::ipmiUserSetbootstrap0InUsed(true);
    }

    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set UserPassword userName {NAME} error code {ERROR}.",
            "NAME", userNameStr, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    /* Set IsBootStrap of bootStrap account to true */
    rc = ipmi::ipmiUserSetUserBootStrapAccountState(userId, true);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User IsBootStrap property userName {NAME} error code {ERROR}.",
            "NAME", userNameStr, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    if (bootstrapControl != ipmi::keepCredBootstrapEnabled)
    {
        lg2::info("Set CredentialBootstrapping to disabled");
        setCredentialBootstrapEnabledProperty(ctx, false);
    }
    else
    {
        lg2::info("Keep credential bootstrapping enabled");
    }

    /*
     * Respond data - per DSP0270 8.1.2 the fields are FIXED width:
     *   bytes[3:18]  User name : 16 bytes, null-terminated and 00h padded
     *   bytes[19:34] Password  : 16 bytes, null-terminated and 00h padded
     * The buffers must therefore be zero-filled to their full width; only
     * appending the string + a single null shifts the password to the wrong
     * offset (the host reads the password from bytes[19:34]) and login fails.
     */
    return ipmi::responseSuccess(userName, password);
}

void registerNetfnRedfishHostInterfaceFunctions() __attribute__((constructor));
void registerNetfnRedfishHostInterfaceFunctions()
{
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupRedfish,
                               ipmi::bootStrap::cmdGetMngCertFingerprint,
                               ipmi::Privilege::User, getFingerprint);
    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, ipmi::groupRedfish,
        ipmi::bootStrap::cmdGetBootstrapAccoutCre, ipmi::Privilege::User,
        getBootstrapAccountCredentials);
    ipmi::registerFilter(ipmi::prioOpenBmcBase,
                         [](ipmi::message::Request::ptr request) {
                             return filterRHICommands(request);
                         });
}
