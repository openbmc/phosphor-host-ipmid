/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <ipmid/types.hpp>

#include <cstddef>
#include <optional>

/** @brief Random user names and passwords for BootStrap accounts
 *
 *  The strings are built to satisfy the policy, so no generate and validate
 *  loop is needed:
 *  - user name: starts with a letter, letters and digits only, at least one
 *    low case letter, one up case letter and one digit
 *  - password: letters, digits and the specials !#$%&()*+,-./:;<=>?@[]^_`{|}~
 *    (printable ASCII punctuation without the quotes and the backslash), at
 *    least one of each kind
 *  - both: no byte equal to the one before it, and no three bytes in a row
 *    stepping by +1 or by -1 (abc, 321)
 *
 *  The user manager has the final say on what it accepts, so callers still
 *  have to handle a rejection, for example by asking for a new password.
 */
namespace bootstrap_credentials
{

/** @brief Buffered random source that hands out unbiased indices
 *
 *  Bytes come from OpenSSL RAND_bytes in blocks. An index in [0, n) is made
 *  by rejection sampling: a byte at or above 256 - (256 % n) is dropped
 *  instead of being reduced with %, which favours the low indices whenever n
 *  does not divide 256. A 64 byte block covers a whole user name or password:
 *  a 15 character password takes about 26 bytes and needs more than 64 with
 *  a probability below 1e-12, and running out only costs another RAND_bytes
 *  call. The block holds the raw material the credentials are derived from,
 *  so it is cleansed when the source goes away.
 */
class ByteSource
{
  public:
    ByteSource() = default;
    ByteSource(const ByteSource&) = delete;
    ByteSource& operator=(const ByteSource&) = delete;
    ~ByteSource();

    /** @brief Uniform random index in [0, n)
     *
     *  @param[in] n - exclusive upper bound, 1..256
     *
     *  @returns the index (0..255), or -1 if n is out of range or the random
     *           source failed
     */
    int next(size_t n);

  private:
    unsigned char pool[64];
    size_t pos = sizeof(pool); // empty, the first call fills it
};

/** @brief Create a random BootStrap account name
 *
 *  @param[in] userNameLength - number of characters
 *
 *  @returns the name, with no terminator, or nullopt if the length is not
 *           supported or the random source failed
 */
std::optional<ipmi::SecureBuffer> createUserName(size_t userNameLength);

/** @brief Create a random BootStrap account password
 *
 *  @param[in] passwordLength - number of characters
 *
 *  @returns the password, with no terminator, or nullopt if the length is not
 *           supported or the random source failed
 */
std::optional<ipmi::SecureBuffer> createPassword(size_t passwordLength);

} // namespace bootstrap_credentials
