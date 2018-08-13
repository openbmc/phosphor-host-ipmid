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
#include <cstring>
#include <fstream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <phosphor-logging/log.hpp>
#include <sys/stat.h>
#include <iomanip>
#include <unistd.h>
#include "file.hpp"

namespace ipmi
{

static const char* PASSWD_FILE_NAME = "/etc/ipmi-pass";
static const char* ENCRYPT_KEY_FILE_NAME = "/etc/key_file";
static const size_t MAX_KEY_SIZE = 8;

#define META_PASSWD_SIG "=OPENBMC="

static inline size_t block_round(size_t odd, size_t blk)
{
    return ((odd) + (((blk) - ((odd) & ((blk)-1))) & ((blk)-1)));
}

/*
 * Meta data struct for encrypted password file
 */
typedef struct metaPassStruct
{
    char signature[10];
    unsigned char reseved[2];
    size_t hashSize;
    size_t ivSize;
    size_t dataSize;
    size_t padSize;
    size_t macSize;
} metaPassStruct;

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
    if (passwdMapList.find(userName) == passwdMapList.end())
    {
        std::string passwd;
        return passwd;
    }
    return passwdMapList[userName];
}

/** @brief Clear user data entry
 *
 *  @param[in] userName - user name
 *
 * @return error response
 */
int PasswdMgr::clearUserEntry(const std::string& userName)
{
    struct stat fileStat;
    if (stat(PASSWD_FILE_NAME, &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return -1;
    }
    std::time_t updatedTime = fileStat.st_mtime;
    // Check file time stamp to know passwdMapList is up-to-date.
    // If not up-to-date, then updatePasswdSpecialFile will read and
    // check the user entry existance.
    if (fileLastUpdatedTime == updatedTime)
    {
        if (passwdMapList.find(userName) == passwdMapList.end())
        {
            log<level::DEBUG>("User not found");
            return -1;
        }
    }

    // Write passwdMap to Encryted file
    if (updatePasswdSpecialFile(userName) != 0)
    {
        log<level::DEBUG>("Passwd file update failed");
        return -1;
    }

    log<level::DEBUG>("Passwd file updated successfully");
    return 0;
}

void PasswdMgr::checkAndReload(void)
{
    struct stat fileStat;
    if (stat(PASSWD_FILE_NAME, &fileStat) != 0)
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

int PasswdMgr::encrypt_decrypt_data(uint8_t isEncrypt, const EVP_CIPHER* cipher,
                                    uint8_t* key, size_t keyLen, uint8_t* iv,
                                    size_t ivLen, uint8_t* inBytes,
                                    size_t inBytesLen, uint8_t* mac,
                                    size_t* macLen, unsigned char* outBytes,
                                    size_t* outBytesLen)
{
    if (cipher == NULL || key == NULL || iv == NULL || inBytes == NULL ||
        outBytes == NULL || mac == NULL || inBytesLen == 0 ||
        (size_t)EVP_CIPHER_key_length(cipher) > keyLen ||
        (size_t)EVP_CIPHER_iv_length(cipher) > ivLen)
    {
        log<level::DEBUG>("Error Invalid Inputs");
        return -1;
    }

    if (!isEncrypt)
    {
        std::array<uint8_t, EVP_MAX_MD_SIZE> calMac;
        size_t calMacLen = calMac.size();
        // calculate MAC for the encrypted message.
        if (NULL == HMAC(EVP_sha256(), key, keyLen, inBytes, inBytesLen,
                         calMac.data(),
                         reinterpret_cast<unsigned int*>(&calMacLen)))
        {
            log<level::DEBUG>("Error Failed to verify authentication");
            return -1;
        }
        if (!((calMacLen == *macLen) &&
              (std::memcmp(calMac.data(), mac, calMacLen) == 0)))
        {
            log<level::DEBUG>("Authenticated message doesn't match");
            return -1;
        }
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

    // Set key & IV
    int retval = EVP_CipherInit_ex(ctx.get(), cipher, NULL, key, iv, isEncrypt);
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

    if (isEncrypt)
    {
        // Create MAC for the encrypted message
        if (NULL == HMAC(EVP_sha256(), key, keyLen, outBytes, *outBytesLen, mac,
                         reinterpret_cast<unsigned int*>(macLen)))
        {
            log<level::DEBUG>("Failed to create authentication");
            return -1;
        }
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
    std::vector<uint8_t> dataBuf;

    if (readPasswdFileData(dataBuf) != 0)
    {
        log<level::DEBUG>("Error in reading the encrypted pass file");
        return;
    }

    if (dataBuf.size() != 0)
    {
        // populate the user list with password
        char* outPtr = (char*)dataBuf.data();
        char* linePtr = strtok(outPtr, "\n");
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
            linePtr = strtok(NULL, "\n");
        }
    }

    // Update the timestamp
    struct stat fileStat;
    if (stat(PASSWD_FILE_NAME, &fileStat) != 0)
    {
        log<level::DEBUG>("Error in getting last updated time stamp");
        return;
    }
    fileLastUpdatedTime = fileStat.st_mtime;
    return;
}

/** @brief Function to read the encrypted password file data.
 *
 *  This function reads the encrypted passwd file and
 *   sends the decrypted data to call along with length
 */
int PasswdMgr::readPasswdFileData(std::vector<uint8_t>& outBytes)
{
    std::array<uint8_t, MAX_KEY_SIZE> keyBuff;
    std::ifstream keyFile(ENCRYPT_KEY_FILE_NAME,
                          std::ios::in | std::ios::binary);
    if (!keyFile.is_open())
    {
        log<level::DEBUG>("Error in opening encryption key file");
        return -1;
    }
    keyFile.read((char*)keyBuff.data(), keyBuff.size());
    if (keyFile.fail() || (keyFile.gcount() != keyBuff.size()))
    {
        log<level::DEBUG>("Error in reading encryption key file");
        return -1;
    }

    std::ifstream passwdFile(PASSWD_FILE_NAME, std::ios::in | std::ios::binary);
    if (!passwdFile.is_open())
    {
        log<level::DEBUG>("Error in opening ipmi password file");
        return -1;
    }

    // calculate file size and read the data
    std::vector<uint8_t> input;
    passwdFile.seekg(0, std::ios::end);
    ssize_t fileSize = passwdFile.tellg();
    passwdFile.seekg(0, std::ios::beg);
    input.resize(fileSize);
    passwdFile.read((char*)input.data(), fileSize);
    if (passwdFile.fail() || (passwdFile.gcount() != fileSize))
    {
        log<level::DEBUG>("Error in reading encryption key file");
        return -1;
    }

    // verify the signature first
    metaPassStruct* metaData = (metaPassStruct*)input.data();
    if (std::strncmp(metaData->signature, META_PASSWD_SIG,
                     sizeof(metaData->signature)))
    {
        log<level::DEBUG>("Error signature mismatch in password file");
        return -1;
    }

    size_t inBytesLen = metaData->dataSize + metaData->padSize;
    // If data is empty i.e no password map then return success
    if (inBytesLen == 0)
    {
        log<level::DEBUG>("Empty password file");
        return 0;
    }

    // compute the key needed to decrypt
    std::array<uint8_t, EVP_MAX_KEY_LENGTH> key;
    size_t keyLen = key.size();
    if (NULL == HMAC(EVP_sha256(), keyBuff.data(), keyBuff.size(),
                     input.data() + sizeof(*metaData), metaData->hashSize,
                     key.data(), reinterpret_cast<unsigned int*>(&keyLen)))
    {
        log<level::DEBUG>("Failed to create MAC for authentication");
        return -1;
    }

    // decrypt the data
    uint8_t* iv = input.data() + sizeof(*metaData) + metaData->hashSize;
    size_t ivLen = metaData->ivSize;
    uint8_t* inBytes = iv + ivLen;
    uint8_t* mac = inBytes + inBytesLen;
    size_t macLen = metaData->macSize;

    size_t outBytesLen = 0;
    // Resize to actual data size
    outBytes.resize(inBytesLen + EVP_MAX_BLOCK_LENGTH);
    if (encrypt_decrypt_data(0, EVP_aes_128_cbc(), key.data(), keyLen, iv,
                             ivLen, inBytes, inBytesLen, mac, &macLen,
                             outBytes.data(), &outBytesLen) != 0)
    {
        log<level::DEBUG>("Error in decryption");
        return -1;
    }
    // Resize the vector to outBytesLen
    outBytes.resize(outBytesLen);

    OPENSSL_cleanse(key.data(), keyLen);
    OPENSSL_cleanse(iv, ivLen);

    return 0;
}

/** @brief Reads passwdMapList and writes to encrypted file
 *
 *  Reads the passwordMapList members, encrypt the data and
 *  write it to password file. passwordMapList will be used
 *  further IPMI authentication.
 */
int PasswdMgr::updatePasswdSpecialFile(const std::string& userName)
{
    phosphor::user::shadow::Lock lock();

    size_t bytesWritten = 0;
    size_t inBytesLen = 0;
    size_t isUsrFound = false;
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    std::vector<uint8_t> dataBuf;

    // Read the encrypted file and get the file data
    // Check user existance and return if not exist.
    if (readPasswdFileData(dataBuf) != 0)
    {
        log<level::DEBUG>("Error in reading the encrypted pass file");
        return -1;
    }

    if (dataBuf.size() != 0)
    {
        inBytesLen = dataBuf.size() + EVP_CIPHER_block_size(cipher);
    }

    std::vector<uint8_t> inBytes(inBytesLen);
    if (inBytesLen != 0)
    {
        char* outPtr = (char*)dataBuf.data();
        size_t userEPos = 0;
        char* linePtr = strtok(outPtr, "\n");
        while (linePtr != NULL)
        {
            std::string lineStr(linePtr);
            if ((userEPos = lineStr.find(":")) != std::string::npos)
            {
                if (userName.compare(lineStr.substr(0, userEPos)) == 0)
                {
                    isUsrFound = true;
                }
                else
                {
                    bytesWritten +=
                        std::snprintf((char*)&inBytes[0] + bytesWritten,
                                      inBytesLen, "%s\n", lineStr.data());
                }
            }
            linePtr = strtok(NULL, "\n");
        }

        // Round of to block size and padding remaing bytes with zero.
        inBytesLen = block_round(bytesWritten, EVP_CIPHER_block_size(cipher));
        memset(&inBytes[0] + bytesWritten, 0, inBytesLen - bytesWritten);
    }

    if (!isUsrFound)
    {
        log<level::DEBUG>("User doesn't exist");
        return -1;
    }

    // Read the key buff from key file
    std::array<uint8_t, MAX_KEY_SIZE> keyBuff;
    std::ifstream keyFile(ENCRYPT_KEY_FILE_NAME,
                          std::ios::in | std::ios::binary);
    if (!keyFile.good())
    {
        log<level::DEBUG>("Error in opening encryption key file");
        return -1;
    }
    keyFile.read((char*)keyBuff.data(), keyBuff.size());
    if (keyFile.fail() || (keyFile.gcount() != keyBuff.size()))
    {
        log<level::DEBUG>("Error in reading encryption key file");
        return -1;
    }
    keyFile.close();

    // Read the original passwd file mode
    struct stat st = {};
    if (stat(PASSWD_FILE_NAME, &st) != 0)
    {
        log<level::DEBUG>("Error in getting password file fstat()");
        return -1;
    }

    // Create temporary file for write
    std::string pwdFile(PASSWD_FILE_NAME);
    std::vector<char> tempFileName(pwdFile.begin(), pwdFile.end());
    std::vector<char> fileTemplate = {'_', '_', 'X', 'X', 'X',
                                      'X', 'X', 'X', '\0'};
    tempFileName.insert(tempFileName.end(), fileTemplate.begin(),
                        fileTemplate.end());
    int fd = mkstemp((char*)tempFileName.data());
    if (fd == -1)
    {
        log<level::DEBUG>("Error creating temp file");
        return -1;
    }

    std::string strTempFileName(tempFileName.data());
    // Open the temp file for writing from provided fd
    // By "true", remove it at exit if still there.
    // This is needed to cleanup the temp file at exception
    phosphor::user::File temp(fd, strTempFileName, "w", true);
    if ((temp)() == NULL)
    {
        close(fd);
        log<level::DEBUG>("Error creating temp file");
        return -1;
    }
    fd = -1; // don't use fd anymore, as the File object owns it

    // Set the file mode as of actual ipmi-pass file.
    if (fchmod(fileno((temp)()), st.st_mode) < 0)
    {
        log<level::DEBUG>("Error setting fchmod for temp file");
        return -1;
    }

    const EVP_MD* digest = EVP_sha256();
    size_t hashLen = EVP_MD_block_size(digest);
    std::vector<uint8_t> hash(hashLen);
    size_t ivLen = EVP_CIPHER_iv_length(cipher);
    std::vector<uint8_t> iv(ivLen);
    std::array<uint8_t, EVP_MAX_KEY_LENGTH> key;
    size_t keyLen = key.size();
    std::array<uint8_t, EVP_MAX_MD_SIZE> mac;
    size_t macLen = mac.size();

    // Create random hash and generate hash key which will be used for
    // encryption.
    if (RAND_bytes(hash.data(), hashLen) != 1)
    {
        log<level::DEBUG>("Hash genertion failed, bailing out");
        return -1;
    }
    if (NULL == HMAC(digest, keyBuff.data(), keyBuff.size(), hash.data(),
                     hashLen, key.data(),
                     reinterpret_cast<unsigned int*>(&keyLen)))
    {
        log<level::DEBUG>("Failed to create MAC for authentication");
        return -1;
    }

    // Generate IV values
    if (RAND_bytes(iv.data(), ivLen) != 1)
    {
        log<level::DEBUG>("UV genertion failed, bailing out");
        return -1;
    }

    // Encrypt the input data
    std::vector<uint8_t> outBytes(inBytesLen + EVP_MAX_BLOCK_LENGTH);
    size_t outBytesLen = 0;
    if (inBytesLen != 0)
    {
        if (encrypt_decrypt_data(1, EVP_aes_128_cbc(), key.data(), keyLen,
                                 iv.data(), ivLen, inBytes.data(), inBytesLen,
                                 mac.data(), &macLen, outBytes.data(),
                                 &outBytesLen) != 0)
        {
            log<level::DEBUG>("Error while encrypting the data");
            return -1;
        }
        outBytes[outBytesLen] = 0;
    }
    OPENSSL_cleanse(key.data(), keyLen);

    // Update the meta password structure.
    metaPassStruct metaData = {META_PASSWD_SIG, {0, 0}, 0, 0, 0, 0, 0};
    metaData.hashSize = hashLen;
    metaData.ivSize = ivLen;
    metaData.dataSize = bytesWritten;
    metaData.padSize = outBytesLen - bytesWritten;
    metaData.macSize = macLen;

    if (fwrite(&metaData, 1, sizeof(metaData), (temp)()) != sizeof(metaData))
    {
        log<level::DEBUG>("Error in writing meta data");
        return -1;
    }

    if (fwrite(&hash[0], 1, hashLen, (temp)()) != hashLen)
    {
        log<level::DEBUG>("Error in writing hash data");
        return -1;
    }

    if (fwrite(&iv[0], 1, ivLen, (temp)()) != ivLen)
    {
        log<level::DEBUG>("Error in writing IV data");
        return -1;
    }

    if (fwrite(&outBytes[0], 1, outBytesLen, (temp)()) != outBytesLen)
    {
        log<level::DEBUG>("Error in writing encrypted data");
        return -1;
    }

    if (fwrite(&mac[0], 1, macLen, (temp)()) != macLen)
    {
        log<level::DEBUG>("Error in writing MAC data");
        return -1;
    }

    if (fflush((temp)()))
    {
        log<level::DEBUG>(
            "File fflush error while writing entries to special file");
        return -1;
    }

    OPENSSL_cleanse(iv.data(), ivLen);

    // Rename the tmp  file to actual file
    if (rename(strTempFileName.data(), PASSWD_FILE_NAME) != 0)
    {
        log<level::DEBUG>("Failed to rename tmp file to ipmi-pass");
        return -1;
    }

    return 0;
}

} // namespace ipmi
