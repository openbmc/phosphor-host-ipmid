/*
 * Copyright (c) 2018-2021 Ampere Computing LLC
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

#include "redfishhostinterface.hpp"

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

#include <iostream>

using namespace phosphor::logging;

bool checkRHIAllowedMediumType(uint8_t mediumType)
{
    if (mediumType ==
            static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20) ||
        mediumType ==
            static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface) ||
        mediumType == static_cast<uint8_t>(ipmi::EChannelMediumType::oem))
    {
        return true;
    }

    return false;
}

X509* loadCert(const std::string& filePath)
{
    BIO* certFileBio = BIO_new_file(filePath.c_str(), "rb");
    if (certFileBio == nullptr)
    {
        lg2::error("Error occurred during BIO_new_file call, path {PATH}",
                   "PATH", filePath);
        return nullptr;
    }

    X509* cert = X509_new();
    if (cert == nullptr)
    {
        lg2::error("Error occurred during X509_new call, {ERROR}", "ERROR",
                   ERR_get_error());
        BIO_free(certFileBio);
        return nullptr;
    }

    if (PEM_read_bio_X509(certFileBio, &cert, nullptr, nullptr) == nullptr)
    {
        lg2::error("Error occurred during PEM_read_bio_X509 call, path {PATH}",
                   "PATH", filePath);

        BIO_free(certFileBio);
        X509_free(cert);
        return nullptr;
    }
    BIO_free(certFileBio);
    return cert;
}

/** @brief implements the get CredentialBootstrapping's Enabled property
 *
 *  @returns 1 - enabled, 0 - disabled, std::nullopt if error
 */
std::optional<bool> getCredentialBootstrapEnabledProperty()
{
    std::string service;
    bool enabled = false;

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    try
    {
        ipmi::Value bootstrapProperty = ipmi::getDbusProperty(
            *bus, ipmi::userMgrService, ipmi::userObjBasePath,
            ipmi::credBootstrappingInf, ipmi::credBootstrapEnabledProp);
        enabled = std::get<bool>(bootstrapProperty);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Can't get value of {PROP} property in the {INF} interface at path {PATH} error {ERROR}",
            "PROP", ipmi::credBootstrapEnabledProp, "INF",
            ipmi::credBootstrappingInf, "PATH", ipmi::userObjBasePath, "ERROR",
            e);
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
ipmi::RspType<std::vector<uint8_t>> getFingerprint(ipmi::Context::ptr ctx,
                                                   uint8_t certNum)
{
    ipmi::ChannelInfo chInfo;
    const std::string certFile = "/etc/ssl/certs/https/server.pem";
    std::vector<uint8_t> dataOut;
    uint8_t cnBuffer[EVP_MAX_MD_SIZE];
    unsigned int cnBufferLen;
    X509* cert;

    if (certNum != 0x1)
    {
        lg2::error("Invalid certNum {CER}.", "CER", certNum);
        return ipmi::responseCertsNumberInvalid();
    }

    try
    {
        ipmi::getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        lg2::error(
            "Get Bootstrap Account: Failed to get Channel Info message {MSG}",
            "MSG", e);
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
    auto enabledState = getCredentialBootstrapEnabledProperty();
    if (!enabledState || (*enabledState == false))
    {
        lg2::error("CredentialBootstrapping is disabled.");
        return ipmi::responseCmdDisabled();
    }

    cert = loadCert(certFile);
    if (cert == nullptr)
    {
        lg2::error("Failed to read cert");
        return ipmi::responseUnspecifiedError();
    }

    if (!X509_digest(cert, EVP_sha256(), cnBuffer, &cnBufferLen))
    {
        lg2::error("Failed to get finger print.");
        X509_free(cert);
        return ipmi::responseUnspecifiedError();
    }

    if (cnBufferLen != ipmi::maxFingerPrintLength)
    {
        lg2::error("Failed to get finger print.");
        X509_free(cert);
        return ipmi::responseUnspecifiedError();
    }
    /* 0x01 for sha256 */
    dataOut.push_back(0x01);
    dataOut.insert(dataOut.end(), cnBuffer,
                   cnBuffer + ipmi::maxFingerPrintLength);

    X509_free(cert);

    return ipmi::responseSuccess(dataOut);
}

ipmi::Cc RHIFilterCommands([[maybe_unused]] ipmi::message::Request::ptr request)
{
    if (request->ctx->netFn != ipmi::netFnGroup ||
        request->ctx->group != ipmi::groupRedfish)
    {
        // Skip if not group SBMR
        return ipmi::ccSuccess;
    }

    ipmi::ChannelInfo chInfo;
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
bool validUserName(std::string useName)
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
 *  @returns one random BootStrap Account Name
 */
std::string createRandomUserName()
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
    std::vector<unsigned char> randomCharType(ipmi::ipmiMaxUserName);
    std::vector<unsigned char> randomChar(ipmi::ipmiMaxUserName);

    if (RAND_bytes(randomCharType.data(), ipmi::ipmiMaxUserName) != 1)
    {
        lg2::error("Error generating random bytes with OpenSSL.");
        return userName;
    }

    if (RAND_bytes(randomChar.data(), ipmi::ipmiMaxUserName) != 1)
    {
        // Handle error if RAND_bytes fails
        lg2::error("Error generating random bytes with OpenSSL.");
        return userName;
    }

    for (auto i = 0; i < ipmi::ipmiMaxUserName; i++)
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
 *  @returns one valid BootStrap Account Name
 */
std::string createUserName()
{
    uint8_t retry = 0;
    std::string userName;
    do
    {
        userName = createRandomUserName();
        if (userName.empty())
        {
            lg2::error("Failed to create BootStrap userName.");
            continue;
        }
        retry++;
    } while (!validUserName(userName) &&
             retry < ipmi::maxCreateRandomUserNameRetry);

    return userName;
}

/** @brief Check whether the password follow the common policy
 *
 *  @param[in] password - password.
 *
 *  @returns true when password is valid, otherwise return false
 */
bool validPassword(std::string password)
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
std::string createRandomPassword(int passwordLength)
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
std::string createPassword(int passwordLength)
{
    uint8_t retry = 0;
    std::string password;
    do
    {
        password = createRandomPassword(passwordLength);
        if (password.empty())
        {
            lg2::error("Failed to create password for BootStrap account.");
            continue;
        }
        retry++;
        std::cerr << " retry " << static_cast<int>(retry) << " password "
                  << password << std::endl;
    } while (!validPassword(password) &&
             retry < ipmi::maxCreateRandomPassworkRetry);

    return password;
}

/** @brief implements the set CredentialBootstrapping's Enabled property
 *
 *  @param[in] pValue - enable status
 *
 *  @returns none
 */
void setCredentialBootstrapEnabledProperty(bool pValue)
{
    std::string service;

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    try
    {
        ipmi::setDbusProperty(*bus, ipmi::userMgrService, ipmi::userObjBasePath,
                              ipmi::credBootstrappingInf,
                              ipmi::credBootstrapEnabledProp, pValue);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Can't set value of {PROP} property in the {INF} interface at path {PATH} error {ERROR}",
            "PROP", ipmi::credBootstrapEnabledProp, "INF",
            ipmi::credBootstrappingInf, "PATH", ipmi::userObjBasePath, "ERROR",
            e);
    }
}

/** @brief Implements the Get bootstrap account credentials command
 *
 *  @param[in] ctx - shared_ptr to an IPMI context struct
 *  @param[in] bootstrapControl - Disable credential bootstrapping control
 *
 *  @returns IPMI completion code plus response data for
 *   - the Get bootstrap account credentials command
 */
ipmi::RspType<std::vector<uint8_t>> /* Output data */
    getBootstrapAccountCredentials(ipmi::Context::ptr ctx,
                                   uint8_t bootstrapControl)
{
    ipmi::ChannelInfo chInfo;
    std::string userName = "";
    std::string password;
    uint8_t userId = 1;
    ipmi::PrivAccess privAccess = {};
    ipmi::UsersTbl* userData;
    uint8_t userCnt = 1; /* One Reserve user account */
    uint8_t retry = 0;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        lg2::error(
            "get Bootstrap Account: Failed to get Channel Info message {MSG}",
            "MSG", e);
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
    auto enabledState = getCredentialBootstrapEnabledProperty();
    if (!enabledState || (*enabledState == false))
    {
        lg2::error("CredentialBootstrapping is disabled.");
        return ipmi::responseCmdDisabled();
    }

    /* Find the user ID empty to set the user name */
    userData = ipmi::getUserAccessObject().getUsersTblPtr();
    for (uint8_t usrIndex = 1; usrIndex < ipmi::ipmiMaxUsers; ++usrIndex)
    {
        if (userData->user[usrIndex].userInSystem)
        {
            userCnt++;
            continue;
        }

        userId = usrIndex;
        break;
    }
    if (userCnt >= ipmi::ipmiMaxUserName)
    {
        lg2::error("Invalid User ID - Out of range");
        return ipmi::responseParmOutOfRange();
    }

    userName = createUserName();
    if (userName.empty())
    {
        lg2::error("Failed to create BootStrap userName.");
        return ipmi::responseUnspecifiedError();
    }

    auto rc = ipmi::ipmiUserSetUserName(userId, userName);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User name userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    retry = 0;
    do
    {
        password = createPassword(ipmi::maxIpmi15PasswordSize);
        if (password.empty())
        {
            lg2::error("Failed to create password for BootStrap account.");
            continue;
        }
        rc = ipmi::ipmiUserSetUserPassword(userId, password.c_str());
        retry++;
    } while (rc != ipmi::ccSuccess && retry < ipmi::maxIpmiUserActionRetry);

    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set UserPassword userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    /* Set user privilege for bootStrap account is User */
    privAccess.privilege = PRIVILEGE_USER;
    rc = ipmi::ipmiUserSetPrivilegeAccess(static_cast<uint8_t>(userId),
                                          ctx->channel, privAccess, 0);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User Privilege Access userName {NAME} error code {ERROR}.",
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

    auto userGroup = {static_cast<std::string>(ipmi::userGroupRedfish)};
    /* Set UserGroup of bootStrap account to {"redfish"} */
    rc = ipmi::ipmiUserSetUserGroups(userId, userName, ctx->channel, userGroup);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error("Failed to create BootStrap userName.");
        return ipmi::responseUnspecifiedError();
    }

    /* Set IsBootStrap of bootStrap account to true */
    rc = ipmi::ipmiUserSetUserIsBootStrapState(userId, userName, true);
    if (rc != ipmi::ccSuccess)
    {
        lg2::error(
            "Failed to set User IsBootStrap property userName {NAME} error code {ERROR}.",
            "NAME", userName, "ERROR", rc);
        return ipmi::responseUnspecifiedError();
    }

    /* Respond data */
    std::vector<uint8_t> dataOut;
    dataOut.insert(dataOut.end(), userName.begin(), userName.end());
    dataOut.push_back('\0');
    dataOut.insert(dataOut.end(), password.begin(), password.end());
    dataOut.push_back('\0');

    if (bootstrapControl != ipmi::keepCredBootstrapEnabled)
    {
        lg2::info("Set CredentialBootstrapping to disabled");
        setCredentialBootstrapEnabledProperty(false);
    }
    else
    {
        lg2::info("Keep credential bootstrapping enabled");
    }

    return ipmi::responseSuccess(dataOut);
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
    ipmi::registerFilter(ipmi::prioOemBase,
                         [](ipmi::message::Request::ptr request) {
                             return RHIFilterCommands(request);
                         });
}
