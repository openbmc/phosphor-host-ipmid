#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "integrity_algo.hpp"
#include "message_parsers.hpp"

namespace cipher
{

namespace integrity
{

Interface::Interface(const Buffer& sik, const Key& addKey, size_t authLength)
{
    unsigned int mdLen = 0;

    // Generated K1 for the integrity algorithm with the additional key keyed
    // with SIK.
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), addKey.data(),
             addKey.size(), K1.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating Key1 for integrity "
                                 "algorithm failed");
    }

    authCodeLength = authLength;
}

Buffer AlgoSHA1::generateHMAC(const uint8_t* input, const size_t len) const
{
    Buffer output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), K1.data(), K1.size(), input, len,
             output.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating integrity data failed");
    }

    // HMAC generates Message Digest to the size of SHA_DIGEST_LENGTH, the
    // AuthCode field length is based on the integrity algorithm. So we are
    // interested only in the AuthCode field length of the generated Message
    // digest.
    output.resize(authCodeLength);

    return output;
}

bool AlgoSHA1::verifyIntegrityData(const Buffer& packet,
                                   const size_t length,
                                   Buffer::const_iterator integrityData) const
{

    auto output = generateHMAC(
            packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
            length);

    // Verify if the generated integrity data for the packet and the received
    // integrity data matches.
    return (std::equal(output.begin(), output.end(), integrityData));
}

Buffer AlgoSHA1::generateIntegrityData(const Buffer& packet) const
{
    return generateHMAC(
            packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
            packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE);
}

}// namespace integrity

}// namespace cipher
