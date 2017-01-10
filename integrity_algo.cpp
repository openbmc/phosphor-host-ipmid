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

}// namespace integrity

}// namespace cipher
