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
     *
     * @return password string. will return empty string, if unable to locate
     * the user
     */
    std::string getPasswdByUserName(const std::string& userName);

  private:
    using UserName = std::string;
    using Password = std::string;
    std::unordered_map<UserName, Password> passwdMapList;
    std::time_t fileLastUpdatedTime;
    /** @brief check timestamp and reload password map if required
     *
     */
    void checkAndReload(void);
    /** @brief initializes passwdMapList by reading the encrypted file
     *
     * Initializes the passwordMapList members after decrypting the
     * password file. passwordMapList will be used further in IPMI
     * authentication.
     */
    void initPasswordMap(void);
    /** @brief decrypts the data provided
     *
     *  @param[in] cipher - cipher to be used
     *  @param[in] key - pointer to the key
     *  @param[in] keyLen - Length of the key to be used
     *  @param[in] iv - pointer to initialization vector
     *  @param[in] ivLen - Length of the iv
     *  @param[in] inBytes - input data to be encrypted / decrypted
     *  @param[in] inBytesLen - input size to be decrypted
     *  @param[in] mac - message authentication code - to figure out corruption
     *  @param[in] macLen - size of MAC
     *  @param[in] outBytes - ptr to store output bytes
     *  @param[in] outBytesLen - outbut data length.
     *
     * @return error response
     */
    int decrypt(const EVP_CIPHER* cipher, uint8_t* key, size_t keyLen,
                uint8_t* iv, size_t ivLen, uint8_t* inBytes, size_t inBytesLen,
                uint8_t* mac, size_t macLen, uint8_t* outBytes,
                size_t* outBytesLen);
};

} // namespace ipmi
