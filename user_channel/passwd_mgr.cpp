/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "passwd_mgr.hpp"

#include "shadowlock.hpp"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <sys/stat.h>

#include <cstring>
#include <fstream>
#include <phosphor-logging/log.hpp>

namespace ipmi
{

static const char* passwdFileName = "/etc/ipmi_pass";
static const char* encryptKeyFileName = "/etc/key_file";
static const size_t maxKeySize = 8;

static const char* META_PASSWD_SIG = "=OPENBMC=";

/*
 * Meta data struct for encrypted password file
 */
struct metaPassStruct
{
    char signature[10];
    unsigned char reseved[2];
    size_t hashSize;
    size_t ivSize;
    size_t dataSize;
    size_t padSize;
    size_t macSize;
};

using namespace phosphor::logging;

PasswdMgr::PasswdMgr()
{
    initPasswordMap();
}

/** @brief Get password for the user
 *
 *  @param[in] userName - user name
 *
 * @return password string. will return empty string, if unable to locate the
 * user
 */
std::string PasswdMgr::getPasswdByUserName(const std::string& userName)
{
    checkAndReload();
    auto iter = passwdMapList.find(userName);
    if (iter == passwdMapList.end())
    {
        return std::string();
    }
    return iter->second;
}

void PasswdMgr::checkAndReload(void)
{
    struct stat fileStat = {};
    if (stat(passwdFileName, &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return;
    }
    std::time_t updatedTime = fileStat.st_mtime;
    if (fileLastUpdatedTime != updatedTime)
    {
        log<level::DEBUG>("Reloading password map list");
        passwdMapList.clear();
        initPasswordMap();
    }
}

int PasswdMgr::decrypt(const EVP_CIPHER* cipher, uint8_t* key, size_t keyLen,
                       uint8_t* iv, size_t ivLen, uint8_t* inBytes,
                       size_t inBytesLen, uint8_t* mac, size_t macLen,
                       uint8_t* outBytes, size_t* outBytesLen)
{

    if (cipher == NULL || key == NULL || iv == NULL || inBytes == NULL ||
        outBytes == NULL || mac == NULL || inBytesLen == 0 ||
        (size_t)EVP_CIPHER_key_length(cipher) > keyLen ||
        (size_t)EVP_CIPHER_iv_length(cipher) > ivLen)
    {
        log<level::DEBUG>("Error Invalid Inputs");
        return -1;
    }

    std::array<uint8_t, EVP_MAX_MD_SIZE> calMac;
    size_t calMacLen = calMac.size();
    // calculate MAC for the encrypted message.
    if (NULL == HMAC(EVP_sha256(), key, keyLen, inBytes, inBytesLen,
                     calMac.data(),
                     reinterpret_cast<unsigned int*>(&calMacLen)))
    {
        log<level::DEBUG>("Error: Failed to calculate MAC");
        return -1;
    }
    if (!((calMacLen == macLen) &&
          (std::memcmp(calMac.data(), mac, calMacLen) == 0)))
    {
        log<level::DEBUG>("Authenticated message doesn't match");
        return -1;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

    // Set key & IV to decrypt
    int retval = EVP_CipherInit_ex(ctx.get(), cipher, NULL, key, iv, 0);
    if (!retval)
    {
        log<level::DEBUG>("EVP_CipherInit_ex failed",
                          entry("RET_VAL=%d", retval));
        return -1;
    }

    int outLen = 0, outEVPLen = 0;
    if ((retval = EVP_CipherUpdate(ctx.get(), outBytes + outLen, &outEVPLen,
                                   inBytes, inBytesLen)))
    {
        outLen += outEVPLen;
        if ((retval =
                 EVP_CipherFinal(ctx.get(), outBytes + outLen, &outEVPLen)))
        {
            outLen += outEVPLen;
            *outBytesLen = outLen;
        }
        else
        {
            log<level::DEBUG>("EVP_CipherFinal fails",
                              entry("RET_VAL=%d", retval));
            return -1;
        }
    }
    else
    {
        log<level::DEBUG>("EVP_CipherUpdate fails",
                          entry("RET_VAL=%d", retval));
        return -1;
    }
    return 0;
}

/** @brief initializes passwdMapList by reading the encrypted file
 *
 *  Initializes the passwordMapList members after decrypting the
 *  password file. passwordMapList will be used further IPMI
 *  authentication.
 */
void PasswdMgr::initPasswordMap(void)
{
    phosphor::user::shadow::Lock lock();

    std::array<uint8_t, maxKeySize> keyBuff;
    std::ifstream keyFile(encryptKeyFileName, std::ios::in | std::ios::binary);
    if (!keyFile.is_open())
    {
        log<level::DEBUG>("Error in opening encryption key file");
        return;
    }
    keyFile.read((char*)keyBuff.data(), keyBuff.size());
    if (keyFile.fail())
    {
        log<level::DEBUG>("Error in reading encryption key file");
        return;
    }

    std::ifstream passwdFile(passwdFileName, std::ios::in | std::ios::binary);
    if (!passwdFile.is_open())
    {
        log<level::DEBUG>("Error in opening ipmi password file");
        return;
    }

    // calculate file size and read the data
    std::vector<uint8_t> input;
    passwdFile.seekg(0, std::ios::end);
    ssize_t fileSize = passwdFile.tellg();
    passwdFile.seekg(0, std::ios::beg);
    input.resize(fileSize);
    passwdFile.read((char*)input.data(), fileSize);
    if (passwdFile.fail())
    {
        log<level::DEBUG>("Error in reading encryption key file");
        return;
    }

    // verify the signature first
    metaPassStruct* metaData = reinterpret_cast<metaPassStruct*>(input.data());
    if (std::strncmp(metaData->signature, META_PASSWD_SIG,
                     sizeof(metaData->signature)))
    {
        log<level::DEBUG>("Error signature mismatch in password file");
        return;
    }

    // compute the key needed to decrypt
    std::array<uint8_t, EVP_MAX_KEY_LENGTH> key;
    size_t keyLen = key.size();
    HMAC(EVP_sha256(), keyBuff.data(), keyBuff.size(),
         input.data() + sizeof(*metaData), metaData->hashSize, key.data(),
         reinterpret_cast<unsigned int*>(&keyLen));

    // decrypt the data
    uint8_t* iv = input.data() + sizeof(*metaData) + metaData->hashSize;
    size_t ivLen = metaData->ivSize;
    uint8_t* inBytes = iv + ivLen;
    size_t inBytesLen = metaData->dataSize + metaData->padSize;
    uint8_t* mac = inBytes + inBytesLen;
    size_t macLen = metaData->macSize;
    std::vector<uint8_t> outBytes(inBytesLen + EVP_MAX_BLOCK_LENGTH);
    size_t outBytesLen = outBytes.size();
    if (decrypt(EVP_aes_128_cbc(), key.data(), keyLen, iv, ivLen, inBytes,
                inBytesLen, mac, macLen, outBytes.data(), &outBytesLen) != 0)
    {
        log<level::DEBUG>("Error in decryption");
        return;
    }
    outBytes[outBytesLen] = 0;
    OPENSSL_cleanse(key.data(), keyLen);
    OPENSSL_cleanse(iv, ivLen);

    // populate the user list with password
    char* outPtr = reinterpret_cast<char*>(outBytes.data());
    char* nToken = NULL;
    char* linePtr = strtok_r(outPtr, "\n", &nToken);
    size_t userEPos = 0, lineSize = 0;
    while (linePtr != NULL)
    {
        std::string lineStr(linePtr);
        if ((userEPos = lineStr.find(":")) != std::string::npos)
        {
            lineSize = lineStr.size();
            passwdMapList.emplace(
                lineStr.substr(0, userEPos),
                lineStr.substr(userEPos + 1, lineSize - (userEPos + 1)));
        }
        linePtr = strtok_r(NULL, "\n", &nToken);
    }
    // Update the timestamp
    struct stat fileStat = {};
    if (stat(passwdFileName, &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return;
    }
    fileLastUpdatedTime = fileStat.st_mtime;
    return;
}

} // namespace ipmi
