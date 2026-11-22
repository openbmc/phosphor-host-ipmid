/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <bootstrap_credentials.hpp>
#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <array>
#include <initializer_list>
#include <numeric>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace bootstrap_credentials
{

namespace
{

constexpr std::string_view lowerChars = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view numericChars = "0123456789";
constexpr std::string_view specialChars = "!#$%&()*+,-./:;<=>?@[]^_`{|}~";

constexpr size_t maxStringLen = 32;
constexpr size_t maxCharSetSize = 92;

/** @brief What a generated BootStrap string has to look like */
struct StringSpec
{
    /* One character from each of these sets is placed at a random position */
    std::span<const std::string_view> required;
    /* Every other position is drawn from this set */
    std::string_view freeSet;
    /* When not empty, position 0 is drawn from this set instead */
    std::string_view firstSet;
};

/** @brief Check whether three bytes in a row step by +1 or by -1 (abc, 321)
 *
 *  @param[in] a, b, c - the bytes, 0 meaning "not placed yet"
 *
 *  @returns true when all three are present and form a run
 */
bool isByteRun(int a, int b, int c)
{
    return a && b && c &&
           ((b - a == 1 && c - b == 1) || (b - a == -1 && c - b == -1));
}

/** @brief Concatenate character sets into one string */
std::string joinSets(std::initializer_list<std::string_view> sets)
{
    std::string joined;
    for (std::string_view set : sets)
    {
        joined += set;
    }
    return joined;
}

/** @brief Generate a random string that satisfies the policy
 *
 *  Policy: one character from each required set, no byte equal to the one
 *  before it, and no three bytes in a row stepping by +1 or by -1. The string
 *  is built left to right, so the policy holds by construction:
 *  1. Slots for the required sets are chosen up front, at random distinct
 *     positions from 1 to len - 1, so every required set is always present.
 *  2. Each position takes the characters of its set that do not break a
 *     neighbour rule given the two bytes already placed, and picks one
 *     uniformly. Excluding at most two characters never empties a set.
 *
 *  @param[in] len - number of characters
 *  @param[in] spec - the sets to draw from
 *
 *  @returns the string, or nullopt if the arguments are out of range or the
 *           random source failed
 */
std::optional<ipmi::SecureBuffer> generateString(size_t len,
                                                 const StringSpec& spec)
{
    if (len == 0 || len > maxStringLen || spec.required.size() >= len ||
        spec.freeSet.size() > maxCharSetSize ||
        spec.firstSet.size() > maxCharSetSize ||
        std::ranges::any_of(spec.required, [](std::string_view set) {
            return set.empty() || set.size() > maxCharSetSize;
        }))
    {
        lg2::error("Invalid BootStrap string request, length {LEN}", "LEN",
                   len);
        return std::nullopt;
    }

    ByteSource source;

    /* The characters allowed at each position of the result */
    std::array<std::string_view, maxStringLen> charSetAt;
    charSetAt.fill(spec.freeSet);
    if (!spec.firstSet.empty())
    {
        charSetAt[0] = spec.firstSet;
    }

    /* Partial Fisher-Yates shuffle picks the slots of the required sets */
    std::array<size_t, maxStringLen> slot;
    std::iota(slot.begin(), slot.begin() + (len - 1), size_t{1});
    for (size_t i = 0; i < spec.required.size(); ++i)
    {
        const int pick = source.next(len - 1 - i);
        if (pick < 0)
        {
            return std::nullopt;
        }
        std::swap(slot[i], slot[i + static_cast<size_t>(pick)]);
        charSetAt[slot[i]] = spec.required[i];
    }

    ipmi::SecureBuffer result(len);
    /* Each candidate set leaves out the byte before it, so it is cleansed
     * along with the result */
    ipmi::SecureBuffer candidates(maxCharSetSize);
    for (size_t i = 0; i < len; ++i)
    {
        const int prev1 = i > 0 ? result[i - 1] : 0;
        const int prev2 = i > 1 ? result[i - 2] : 0;

        size_t count = 0;
        for (char setChar : charSetAt[i])
        {
            const auto ch = static_cast<unsigned char>(setChar);
            if (ch != prev1 && !isByteRun(prev2, prev1, ch))
            {
                candidates[count++] = ch;
            }
        }

        const int pick = source.next(count);
        if (pick < 0)
        {
            return std::nullopt;
        }
        result[i] = candidates[static_cast<size_t>(pick)];
    }
    return result;
}

} // namespace

ByteSource::~ByteSource()
{
    OPENSSL_cleanse(pool, sizeof(pool));
}

int ByteSource::next(size_t n)
{
    if (n == 0 || n > 256)
    {
        return -1;
    }

    // pick a limit to a multiple of n so 'byte % n' later doesn't cause a bias
    const unsigned limit = static_cast<unsigned>(256 - (256 % n));
    for (;;)
    {
        if (pos == sizeof(pool))
        {
            if (RAND_bytes(pool, sizeof(pool)) != 1)
            {
                lg2::error("Error generating random bytes with OpenSSL.");
                return -1;
            }
            pos = 0;
        }
        const unsigned char byte = pool[pos++];
        if (byte < limit)
        {
            return static_cast<int>(byte % n);
        }
    }
}

std::optional<ipmi::SecureBuffer> createUserName(size_t userNameLength)
{
    static const std::string alphaChars = joinSets({lowerChars, upperChars});
    static const std::string alnumChars =
        joinSets({lowerChars, upperChars, numericChars});
    static constexpr std::array<std::string_view, 3> required{
        lowerChars, upperChars, numericChars};

    return generateString(userNameLength, {required, alnumChars, alphaChars});
}

std::optional<ipmi::SecureBuffer> createPassword(size_t passwordLength)
{
    static const std::string allChars =
        joinSets({lowerChars, upperChars, numericChars, specialChars});
    static constexpr std::array<std::string_view, 4> required{
        lowerChars, upperChars, numericChars, specialChars};

    return generateString(passwordLength, {required, allChars, {}});
}

} // namespace bootstrap_credentials
