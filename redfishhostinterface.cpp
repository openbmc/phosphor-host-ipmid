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

using namespace phosphor::logging;

static constexpr const char* credBootstrappingInf =
    "xyz.openbmc_project.HostInterface.CredentialBootstrapping";
static constexpr const char* credBootstrapEnabledProp = "Enabled";

bool checkRHIAllowedMediumType(const uint8_t& mediumType)
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
    std::string service;
    bool enabled = false;

    try
    {
        ipmi::Value bootstrapProperty = ipmi::getDbusProperty(
            *ctx->bus, ipmi::userMgrService, ipmi::userObjBasePath,
            credBootstrappingInf, credBootstrapEnabledProp);
        enabled = std::get<bool>(bootstrapProperty);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Can't get value of {PROP} property in the {INF} interface at path {PATH} error {ERROR}",
            "PROP", credBootstrapEnabledProp, "INF", credBootstrappingInf,
            "PATH", ipmi::userObjBasePath, "ERROR", e);
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
    ipmi::ChannelInfo chInfo;
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

void registerNetfnRedfishHostInterfaceFunctions() __attribute__((constructor));
void registerNetfnRedfishHostInterfaceFunctions()
{
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupRedfish,
                               ipmi::bootStrap::cmdGetMngCertFingerprint,
                               ipmi::Privilege::User, getFingerprint);
    ipmi::registerFilter(ipmi::prioOpenBmcBase,
                         [](ipmi::message::Request::ptr request) {
                             return filterRHICommands(request);
                         });
}
