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

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <user_channel/user_layer.hpp>
#include <user_channel/user_mgmt.hpp>

#include <filesystem>
#include <map>
#include <ranges>
#include <unordered_set>

using namespace phosphor::logging;

static constexpr const char* credBootstrappingInf =
    "xyz.openbmc_project.HostInterface.CredentialBootstrapping";
static constexpr const char* credBootstrapEnabledProp = "Enabled";
static constexpr const char* credBootstrapRoleIdProp = "RoleId";

/* Default name of first bootStrap account */
static constexpr const char* firstUserName = "bootstrap0";

/*
 * There no channel info when create the bootStrap account
 * Use default channel
 */
constexpr uint8_t defaultChannelNum = 0x1;

std::map<std::string, CommandPrivilege> credentialRoleIdToUserPriv = {
    {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.Administrator",
     CommandPrivilege::PRIVILEGE_ADMIN},
    {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.Operator",
     CommandPrivilege::PRIVILEGE_OPERATOR},
    {"xyz.openbmc_project.HostInterface.CredentialBootstrapping.Role.ReadOnly",
     CommandPrivilege::PRIVILEGE_USER}};

namespace ipmi
{

/* BootStrap Account commands */
/* Completion code */
constexpr Cc ccCredsBootstrapDisabled = 0x80;
constexpr Cc ccCertificateNumberInvalid = 0xCB;

/* Credential bootstrapping control option */
constexpr uint8_t keepCredBootstrapEnabled = 0xa5;

/* 32 bytes of the fingerprint */
static constexpr size_t maxFingerPrintLength = 32;

namespace bootStrap
{
constexpr Cmd cmdGetMngCertFingerprint = 0x01;
constexpr Cmd cmdGetBootstrapAccoutCre = 0x02;
} // namespace bootStrap

/* helper functions for the various bootStrap command error response types */
static inline auto responseCmdDisabled()
{
    return response(ccCredsBootstrapDisabled);
}

static inline auto responseCertsNumberInvalid()
{
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

bool checkRHIAllowedMediumType(const uint8_t& mediumType)
{
    if (mediumType == static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20))
    {
        return true;
    }

    return false;
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
    ipmi::ChannelInfo chInfo{};
    const std::string certFile = "/etc/ssl/certs/https/server.pem";
    uint8_t cnBuffer[EVP_MAX_MD_SIZE];
    unsigned int cnBufferLen;

    if (certNum != 0x1)
    {
        lg2::error("Invalid certNum {CER}.", "CER", certNum);
        return ipmi::responseCertsNumberInvalid();
    }

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

    auto cert = loadCert(certFile);
    if (cert == nullptr)
    {
        lg2::error("Failed to read cert");
        return ipmi::responseUnspecifiedError();
    }

    if (!X509_digest(cert.get(), EVP_sha256(), cnBuffer, &cnBufferLen))
    {
        lg2::error("Failed to get finger print.");
        return ipmi::responseUnspecifiedError();
    }

    if (cnBufferLen != ipmi::maxFingerPrintLength)
    {
        lg2::error("Failed to get finger print.");
        return ipmi::responseUnspecifiedError();
    }
    constexpr uint8_t sha256Type = 0x01;
    std::vector<uint8_t> hashData{cnBuffer, cnBuffer + cnBufferLen};

    return ipmi::responseSuccess(sha256Type, hashData);
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

/** @brief Check whether the user name is valid
 *
 *  @param[in] userName - user name which needs validate.
 *
 *  @returns true when userName is valid, otherwise return false
 */
bool validUserName(const std::string& useName)
{
    bool haveUpChar = false;
    bool haveLowChar = false;
    std::string lowCharacters = static_cast<std::string>(ipmi::lowCharacters);
    std::string upCharacters = static_cast<std::string>(ipmi::upCharacters);
    std::string numberCharacters =
        static_cast<std::string>(ipmi::numberCharacters);

    for (auto& useNameChar : useName)
    {
        if (lowCharacters.find(useNameChar) != std::string::npos)
        {
            haveLowChar = true;
            continue;
        }
        if (upCharacters.find(useNameChar) != std::string::npos)
        {
            haveUpChar = true;
            continue;
        }
    }

    if (haveLowChar && haveUpChar)
    {
        return true;
    }

    return false;
}

/** @brief Create random BootStrap Account Name
 *
 *  @param[in] userNameLength - user name length
 *
 *  @returns one random BootStrap Account Name
 */
std::string createRandomUserName(const uint8_t& userNamelength)
{
    /*
     * Create random username has 16 characters and follow this policy
     * + Include 16 characters
     * + Must include at least one Low case character
     * + Must include at least one Up case character
     * + Must include at least one number character
     */
    std::string userName = "";
    std::string lowCharacters = static_cast<std::string>(ipmi::lowCharacters);
    std::string upCharacters = static_cast<std::string>(ipmi::upCharacters);
    std::string numberCharacters =
        static_cast<std::string>(ipmi::numberCharacters);
    std::vector<unsigned char> randomCharType(userNamelength);
    std::vector<unsigned char> randomChar(userNamelength);

    if (RAND_bytes(randomCharType.data(), userNamelength) != 1)
    {
        lg2::error("Error generating random bytes with OpenSSL.");
        return userName;
    }

    if (RAND_bytes(randomChar.data(), userNamelength) != 1)
    {
        // Handle error if RAND_bytes fails
        lg2::error("Error generating random bytes with OpenSSL.");
        return userName;
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
                userName +=
                    lowCharacters[randomChar[i] % lowCharacters.length()];
                break;
            case 1:
                userName += upCharacters[randomChar[i] % upCharacters.length()];
                break;
            case 2:
                userName +=
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
std::string createUserName(const uint8_t& userNameLength)
{
    std::string userName;
    for ([[maybe_unused]] auto i : std::views::iota(
             0, static_cast<int>(ipmi::maxCreateRandomUserNameRetry)))
    {
        userName = createRandomUserName(userNameLength);
        if (userName.empty())
        {
            lg2::error("Failed to create BootStrap userName.");
            continue;
        }
        if (validUserName(userName))
        {
            return userName;
        }
    }

    return "";
}

/** @brief Check whether the password follow the common policy
 *
 *  @param[in] password - password.
 *
 *  @returns true when password is valid, otherwise return false
 */
bool validPassword(const std::string& password)
{
    bool haveUpChar = false;
    bool haveLowChar = false;
    bool haveNumberChar = false;
    bool haveSpecialChar = false;
    std::string lowCharacters = static_cast<std::string>(ipmi::lowCharacters);
    std::string upCharacters = static_cast<std::string>(ipmi::upCharacters);
    std::string numberCharacters =
        static_cast<std::string>(ipmi::numberCharacters);
    std::string specialCharacters =
        static_cast<std::string>(ipmi::specialCharacters);

    for (auto& passwordChar : password)
    {
        if (lowCharacters.find(passwordChar) != std::string::npos)
        {
            haveLowChar = true;
            continue;
        }
        if (upCharacters.find(passwordChar) != std::string::npos)
        {
            haveUpChar = true;
            continue;
        }
        if (numberCharacters.find(passwordChar) != std::string::npos)
        {
            haveNumberChar = true;
            continue;
        }
        if (specialCharacters.find(passwordChar) != std::string::npos)
        {
            haveSpecialChar = true;
            continue;
        }
    }

    if (haveLowChar && haveUpChar && haveNumberChar && haveSpecialChar)
    {
        return true;
    }

    return false;
}

/** @brief Create one random user password
 *
 *  @param[in] passwordLength - length of the random password.
 *
 *  @returns one random password
 */
std::string createRandomPassword(const uint8_t& passwordLength)
{
    /*
     * Create random password has 16 characters and follow common policy
     * + Include 16 characters
     * + Must include at least one Low case character
     * + Must include at least one Up case character
     * + Must include at least one number character
     * + Must include at least one special character
     */
    std::string password = "";
    std::string lowCharacters = static_cast<std::string>(ipmi::lowCharacters);
    std::string upCharacters = static_cast<std::string>(ipmi::upCharacters);
    std::string numberCharacters =
        static_cast<std::string>(ipmi::numberCharacters);
    std::string specialCharacters =
        static_cast<std::string>(ipmi::specialCharacters);
    std::vector<unsigned char> randomCharType(passwordLength);
    std::vector<unsigned char> randomChar(passwordLength);

    if (RAND_bytes(randomCharType.data(), passwordLength) != 1)
    {
        lg2::error("Error generating random bytes with OpenSSL.");
        return password;
    }

    if (RAND_bytes(randomChar.data(), passwordLength) != 1)
    {
        // Handle error if RAND_bytes fails
        lg2::error("Error generating random bytes with OpenSSL.");
        return password;
    }

    for (auto i = 0; i < passwordLength; i++)
    {
        auto type = randomCharType[i] % ipmi::passwordCharacterTypes;
        switch (type)
        {
            case 0:
                password +=
                    lowCharacters[randomChar[i] % lowCharacters.length()];
                break;
            case 1:
                password += upCharacters[randomChar[i] % upCharacters.length()];
                break;
            case 2:
                password +=
                    numberCharacters[randomChar[i] % numberCharacters.length()];
                break;
            case 3:
                password += specialCharacters[randomChar[i] %
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
std::string createPassword(const uint8_t& passwordLength)
{
    std::string password;
    for ([[maybe_unused]] auto i : std::views::iota(
             0, static_cast<int>(ipmi::maxCreateRandomPassworkRetry)))
    {
        password = createRandomPassword(passwordLength);
        if (password.empty())
        {
            lg2::error("Failed to create password for BootStrap account.");
            continue;
        }
        if (validPassword(password))
        {
            return password;
        }
    }

    return "";
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

std::optional<std::unordered_set<std::string>> getAvailableUserLists(
    ipmi::Context::ptr ctx)
{
    using Paths = std::vector<std::string>;
    std::unordered_set<std::string> userPaths;
    boost::system::error_code ec;

    Paths paths = ipmi::callDbusMethod<Paths>(
        ctx, ec, ipmi::MAPPER_BUS_NAME, ipmi::MAPPER_OBJ, ipmi::MAPPER_INTF,
        "GetSubTreePaths", "/xyz/openbmc_project/user", int32_t(0),
        std::array<const char*, 1>{ipmi::usersInterface});

    if (ec)
    {
        return std::nullopt;
    }
    for (auto path : paths)
    {
        userPaths.emplace(std::filesystem::path(path).filename());
    }

    return userPaths;
}

/** @brief Implements the Get bootstrap account credentials command
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] bootstrapControl - Disable credential bootstrapping control
 *
 *  @returns IPMI completion code plus response data for
 *   - the Get bootstrap account credentials command
 */
ipmi::RspType<std::vector<uint8_t>, /* 16 bytes user name */
              std::vector<uint8_t>> /* 16 bytes user password */
    getBootstrapAccountCredentials(ipmi::Context::ptr ctx,
                                   uint8_t bootstrapControl)
{
    ipmi::ChannelInfo chInfo{};
    std::string userName = "";
    std::string password;
    uint8_t userId = 1;
    ipmi::PrivAccess privAccess = {};
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
    auto listUsers = getAvailableUserLists(ctx);
    userName = firstUserName;
    if (listUsers && (listUsers->find(userName) != listUsers->end()))
    {
        userName = createUserName(ipmi::ipmiMaxUserName - 1);
    }

    if (userName.empty())
    {
        lg2::error("Failed to create BootStrap userName.");
        return ipmi::responseUnspecifiedError();
    }

    if (ipmi::ipmiUserAddUserToNonIpmiGroupUsers(userName) != ipmi::ccSuccess)
    {
        lg2::error("Non-ipmi User limit reached");
        return ipmi::responseOutOfSpace();
    }

    auto rc = ipmi::ipmiUserSetUserName(userId, userName);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User name userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
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
        rc = ipmi::ipmiUserSetUserPassword(userId, password.c_str());
        if (rc == ipmi::ccSuccess)
        {
            break;
        }
    }

    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set UserPassword userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    /* Set user privilege for bootStrap account is User */
    privAccess.privilege = getRedfishHostInterfacePriv(ctx);
    rc = ipmi::ipmiUserSetPrivilegeAccess(static_cast<uint8_t>(userId),
                                          defaultChannelNum, privAccess, 0);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User Privilege Access userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    auto userGroup = {static_cast<std::string>(ipmi::redfishGrpName)};
    /* Set UserGroup of bootStrap account to {"redfish"} */
    rc = ipmi::ipmiUserSetUserGroups(userId, defaultChannelNum, userGroup);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error("Failed to create BootStrap userName.");
        return ipmi::responseUnspecifiedError();
    }

    /* Set IsBootStrap of bootStrap account to true */
    rc = ipmi::ipmiUserSetUserBootStrapAccountState(userId, true);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User IsBootStrap property userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    /* Enable user */
    rc = ipmi::ipmiUserUpdateEnabledState(userId, true);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error("Failed to enable userName {NAME} error code {ERROR}.",
                   "NAME", userName, "ERROR", rc);
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

    /* Respond data */
    std::vector<uint8_t> vUserName;
    vUserName.insert(vUserName.end(), userName.begin(), userName.end());
    vUserName.push_back('\0');
    std::vector<uint8_t> vPassword;
    vPassword.insert(vPassword.end(), password.begin(), password.end());
    vPassword.push_back('\0');

    return ipmi::responseSuccess(vUserName, vPassword);
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
