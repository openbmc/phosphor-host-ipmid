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
#pragma once
#include <openssl/evp.h>

#include <ctime>
#include <unordered_map>
#include <vector>

namespace ipmi
{

class PasswdMgr
{
  public:
    ~PasswdMgr() = default;
    PasswdMgr(const PasswdMgr&) = delete;
    PasswdMgr& operator=(const PasswdMgr&) = delete;
    PasswdMgr(PasswdMgr&&) = delete;
    PasswdMgr& operator=(PasswdMgr&&) = delete;

    /** @brief Constructs user password list
     *
     */
    PasswdMgr();

    /** @brief Get password for the user
     *
     *  @param[in] userName - user name
     */
    std::string getPasswdByUserName(const std::string& userName);

    /** @brief Clear username and password entry for the specified user
     *
     *  @param[in] userName - user name that has to be renamed / deleted
     *  @param[in] newUserName - new user name. If empty, userName will be
     *   deleted.
     *
     * @return error response
     */
    int updateUserEntry(const std::string& userName,
                        const std::string& newUserName);

  private:
    std::unordered_map<std::string, std::string> passwdMapList;
    std::time_t fileLastUpdatedTime;
    /** @brief check timestamp and reload password map if required
     *
     */
    void checkAndReload(void);
    /** @brief initializes passwdMapList by reading the encrypted file
     *
     */
    void initPasswordMap(void);
    /** @brief Function to read the password file data
     *
     *  @param[out] outBytes - vector to hold decrypted password file data
     *
     * @return error response
     */
    int readPasswdFileData(std::vector<uint8_t>& outBytes);
    /** @brief  Updates special password file by clearing the password entry
     *  for the user specified.
     *
     *  @param[in] userName - user name that has to be renamed / deleted
     *  @param[in] newUserName - new user name. If empty, userName will be
     *   deleted.
     *
     * @return error response
     */
    int updatePasswdSpecialFile(const std::string& userName,
                                const std::string& newUserName);
    /** @brief encrypts or decrypt the data provided
     *
     *  @param[in] isEncrypt - do encrypt if set to 1, else do decrypt.
     *  @param[in] cipher - cipher to be used
     *  @param[in] key - pointer to the key
     *  @param[in] keyLen - Length of the key to be used
     *  @param[in] iv - pointer to initialization vector
     *  @param[in] ivLen - Length of the iv
     *  @param[in] inBytesLen - input data to be encrypted / decrypted
     *  @param[in] inBytesLen - input size to be encrypted / decrypted
     *  @param[in] mac - message authentication code - to figure out corruption
     *  @param[in] macLen - size of MAC
     *  @param[in] outBytes - ptr to store output bytes
     *  @param[in] outBytesLen - outbut data length.
     *
     * @return error response
     */
    int encryptDecryptData(uint8_t isEncrypt, const EVP_CIPHER* cipher,
                           uint8_t* key, size_t keyLen, uint8_t* iv,
                           size_t ivLen, uint8_t* inBytes, size_t inBytesLen,
                           uint8_t* mac, size_t* macLen, uint8_t* outBytes,
                           size_t* outBytesLen);
};

} // namespace ipmi
