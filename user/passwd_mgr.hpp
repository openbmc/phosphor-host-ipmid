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
#include <ctime>
#include <openssl/evp.h>
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
         */
        std::string getPasswdByUserName(const std::string& userName);

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
        /** @brief decrypts the data provided
         *
         */
        int decrypt(const EVP_CIPHER* cipher, uint8_t* key, size_t keyLen,
                    uint8_t* iv, size_t ivLen, uint8_t* inBytes, size_t inBytesLen,
                    uint8_t* mac, size_t macLen, uint8_t* outBytes,
                    size_t* outBytesLen);
};

} // namespace ipmi
