#pragma once

#include <openssl/sha.h>
#include <array>
#include <vector>

namespace cipher
{

namespace crypt
{

using buffer = std::vector<uint8_t>;
using key = std::array<uint8_t, SHA_DIGEST_LENGTH>;

/**
 * @enum Confidentiality Algorithms
 *
 * The Confidentiality Algorithm Number specifies the encryption/decryption
 * algorithm field that is used for encrypted payload data under the session.
 * The ‘encrypted’ bit in the payload type field being set identifies packets
 * with payloads that include data that is encrypted per this specification.
 * When payload data is encrypted, there may be additional “Confidentiality
 * Header” and/or “Confidentiality Trailer” fields that are included within the
 * payload. The size and definition of those fields is specific to the
 * particular confidentiality algorithm.
 */
enum class Algorithms : uint8_t
{
    NONE,               /**< No encryption (mandatory option) */
    AES_CBC_128,        /**< AES-CBC-128 Algorithm (mandatory option) */
    xRC4_128,           /**< xRC4-128 Algorithm (optional option) */
    xRC4_40,            /**< xRC4-40 Algorithm (optional option) */
};

/**
 * @class Interface
 *
 * Interface is the base class for the Confidentiality Algorithms.
 */
class Interface
{
    public:
        /**
         * @brief Constructor for Interface
         *
         * @param[in] - Session Integrity key to generate K2
         * @param[in] - Additional keying material to generate K2
         */
        explicit Interface(const buffer& sik, const key& addKey);

        Interface() = delete;
        virtual ~Interface() = default;
        Interface(const Interface&) = default;
        Interface& operator=(const Interface&) = default;
        Interface(Interface&&) = default;
        Interface& operator=(Interface&&) = default;

        /**
         * @brief Decrypt the incoming payload
         *
         * @param[in] packet - Incoming IPMI packet
         * @param[in] sessHeaderLen - Length of the IPMI Session Header
         * @param[in] payloadLen - Length of the encrypted IPMI payload
         *
         * @return decrypted payload if the operation is successful
         */
        virtual buffer decryptPayload(
                const buffer& packet,
                const size_t sessHeaderLen,
                const size_t payloadLen) const = 0;

        /**
         * @brief Encrypt the outgoing payload
         *
         * @param[in] payload - plain payload for the outgoing IPMI packet
         *
         * @return encrypted payload if the operation is successful
         *
         */
        virtual buffer encryptPayload(buffer& payload) const = 0;

    protected:

        /** @brief K2 is the key used for encrypting data */
        key k2;
};

}// namespace crypt

}// namespace cipher

