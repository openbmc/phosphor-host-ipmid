#include "auth_algo.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <iostream>

namespace cipher
{

namespace rakp_auth
{

const std::string userName = "admin";

std::vector<uint8_t>
    AlgoSHA1::generateHMAC(const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), userKey.data(), userKey.size(), input.data(),
             input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC failed\n";
        output.resize(0);
    }

    return output;
}

std::vector<uint8_t>
    AlgoSHA1::generateICV(const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), sessionIntegrityKey.data(), SHA_DIGEST_LENGTH,
             input.data(), input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate Session Integrity Key failed\n";
        output.resize(0);
    }
    output.resize(integrityCheckValueLength);

    return output;
}

std::vector<uint8_t>
    AlgoSHA256::generateHMAC(const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha256(), userKey.data(), userKey.size(), input.data(),
             input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC_SHA256 failed\n";
        output.resize(0);
    }

    return output;
}

std::vector<uint8_t>
    AlgoSHA256::generateICV(const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha256(), sessionIntegrityKey.data(),
             sessionIntegrityKey.size(), input.data(), input.size(),
             output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC_SHA256_128 Integrity Check Value failed\n";
        output.resize(0);
    }
    output.resize(integrityCheckValueLength);

    return output;
}

} // namespace rakp_auth

} // namespace cipher
