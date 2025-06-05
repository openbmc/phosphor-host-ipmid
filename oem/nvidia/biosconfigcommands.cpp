#include "config.h"

#include "oemcommands.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <array>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

constexpr char biosPasswordFilePath[] =
    "/var/lib/bios-settings-manager/seedData";
constexpr int biosPasswordIter = 1000;
constexpr uint8_t biosPasswordSaltSize = 32;
constexpr uint8_t biosPasswordMaxHashSize = 64;
constexpr uint8_t biosPasswordTypeNoChange = 0x00;
constexpr uint8_t biosPasswordSelectorAdmin = 0x01;
constexpr uint8_t biosPasswordTypeNoPassowrd = 0x01;
constexpr uint8_t biosPasswordTypePbkdf2Sha256 = 0x02;
constexpr uint8_t biosPasswordTypePbkdf2Sha384 = 0x03;

void registerBiosConfigCommands() __attribute__((constructor));

namespace ipmi
{
ipmi::RspType<> ipmiSetBiosPassword(
    uint8_t id, uint8_t type, std::array<uint8_t, biosPasswordSaltSize> salt,
    std::array<uint8_t, biosPasswordMaxHashSize> hash)
{
    nlohmann::json json;

    if (id != biosPasswordSelectorAdmin)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    // key names for json object
    constexpr char keyHashAlgo[] = "HashAlgo";
    constexpr char keySeed[] = "Seed";
    constexpr char keyAdminPwdHash[] = "AdminPwdHash";
    constexpr char keyIsAdminPwdChanged[] = "IsAdminPwdChanged";
    constexpr char keyIsUserPwdChanged[] = "IsUserPwdChanged";
    constexpr char keyUserPwdHash[] = "UserPwdHash";

    switch (type)
    {
        case biosPasswordTypeNoPassowrd:
            json[keyHashAlgo] = "SHA256";
            RAND_bytes(salt.data(), salt.size());
            // password is only Null-terminated character
            PKCS5_PBKDF2_HMAC("", 1, salt.data(), salt.size(), biosPasswordIter,
                              EVP_sha256(), SHA256_DIGEST_LENGTH, hash.data());
            json[keySeed] = salt;
            json[keyAdminPwdHash] = hash;
            break;
        case biosPasswordTypePbkdf2Sha256:
            json[keyHashAlgo] = "SHA256";
            json[keySeed] = salt;
            json[keyAdminPwdHash] = hash;
            break;
        case biosPasswordTypePbkdf2Sha384:
            json[keyHashAlgo] = "SHA384";
            json[keySeed] = salt;
            json[keyAdminPwdHash] = hash;
            break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    json[keyIsAdminPwdChanged] = false;
    json[keyIsUserPwdChanged] = false;

    // initializing with 0 as user password hash field
    // is not used presently
    constexpr std::array<uint8_t, biosPasswordMaxHashSize> userPwdHash = {0};
    json[keyUserPwdHash] = userPwdHash;

    try
    {
        std::ofstream ofs(biosPasswordFilePath, std::ios::out);
        const auto& writeData = json.dump();
        ofs << writeData;
        ofs.close();
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to save BIOS Password information: {ERROR}", "ERROR",
                   e.what());
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t,                                     // action
              std::array<uint8_t, biosPasswordSaltSize>,   // salt
              std::array<uint8_t, biosPasswordMaxHashSize> // hash
              >
    ipmiGetBiosPassword(uint8_t id)
{
    uint8_t action = biosPasswordTypeNoChange;
    std::array<uint8_t, biosPasswordSaltSize> salt = {0};
    std::array<uint8_t, biosPasswordMaxHashSize> hash = {0};

    if (id != biosPasswordSelectorAdmin)
    {
        return ipmi::responseParmOutOfRange();
    }

    std::ifstream ifs(biosPasswordFilePath);
    if (!ifs.is_open())
    {
        // return No change if no file
        return ipmi::responseSuccess(action, salt, hash);
    }

    nlohmann::json json = nlohmann::json::parse(ifs, nullptr, false);
    if (json.is_discarded() || !json.contains("IsAdminPwdChanged") ||
        !json.contains("HashAlgo") || !json.contains("Seed") ||
        !json.contains("AdminPwdHash"))
    {
        return ipmi::responseResponseError();
    }
    bool IsAdminPwdChanged = json["IsAdminPwdChanged"];
    if (IsAdminPwdChanged == false)
    {
        return ipmi::responseSuccess(action, salt, hash);
    }

    salt = json["Seed"];
    hash = json["AdminPwdHash"];

    std::string HashAlgo = json["HashAlgo"];
    auto digest = EVP_sha256();
    int keylen = SHA256_DIGEST_LENGTH;

    if (HashAlgo == "SHA256")
    {
        action = biosPasswordTypePbkdf2Sha256;
    }
    else if (HashAlgo == "SHA384")
    {
        action = biosPasswordTypePbkdf2Sha384;
        digest = EVP_sha384();
        keylen = SHA384_DIGEST_LENGTH;
    }

    std::array<uint8_t, biosPasswordMaxHashSize> nullHash = {0};
    PKCS5_PBKDF2_HMAC("", 1, salt.data(), salt.size(), biosPasswordIter, digest,
                      keylen, nullHash.data());
    if (hash == nullHash)
    {
        action = biosPasswordTypeNoPassowrd;
        salt.fill(0x00);
        hash.fill(0x00);
    }

    return ipmi::responseSuccess(action, salt, hash);
}
} // namespace ipmi

void registerBiosConfigCommands()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::groupNvidia,
                          ipmi::bios_password::cmdSetBiosPassword,
                          ipmi::Privilege::Admin, ipmi::ipmiSetBiosPassword);
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::groupNvidia,
                          ipmi::bios_password::cmdGetBiosPassword,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPassword);
}
