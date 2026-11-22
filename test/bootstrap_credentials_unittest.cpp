/*
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <bootstrap_credentials.hpp>

#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace
{

using bootstrap_credentials::ByteSource;
using bootstrap_credentials::createPassword;
using bootstrap_credentials::createUserName;

/* The checks below are written out on their own, not shared with the
 * generator, so a mistake in one cannot hide a mistake in the other. */
constexpr std::string_view lower = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view digits = "0123456789";
constexpr std::string_view specials = "!#$%&()*+,-./:;<=>?@[]^_`{|}~";

/* Each generated string is checked this many times. The generator is cheap,
 * so a large count costs little and makes a rare policy break show up. */
constexpr int iterations = 100000;

constexpr size_t nameLength = 16;
constexpr size_t passwordLength = 16;

bool contains(std::string_view set, char c)
{
    return set.find(c) != std::string_view::npos;
}

bool anyIn(std::string_view str, std::string_view set)
{
    return str.find_first_of(set) != std::string_view::npos;
}

/* No byte repeats its predecessor, no three bytes step by +1 or by -1 */
bool neighborsOk(std::string_view str)
{
    for (size_t i = 1; i < str.size(); ++i)
    {
        if (str[i] == str[i - 1])
        {
            return false;
        }
        if (i > 1)
        {
            const int step1 = str[i - 1] - str[i - 2];
            const int step2 = str[i] - str[i - 1];
            if ((step1 == 1 && step2 == 1) || (step1 == -1 && step2 == -1))
            {
                return false;
            }
        }
    }
    return true;
}

bool userNameOk(std::string_view name)
{
    if (name.size() != nameLength)
    {
        return false;
    }
    if (!contains(lower, name.front()) && !contains(upper, name.front()))
    {
        return false;
    }
    for (char c : name)
    {
        if (!contains(lower, c) && !contains(upper, c) && !contains(digits, c))
        {
            return false;
        }
    }
    return anyIn(name, lower) && anyIn(name, upper) && anyIn(name, digits) &&
           neighborsOk(name);
}

bool passwordOk(std::string_view password)
{
    if (password.size() != passwordLength)
    {
        return false;
    }
    for (char c : password)
    {
        if (!contains(lower, c) && !contains(upper, c) &&
            !contains(digits, c) && !contains(specials, c))
        {
            return false;
        }
    }
    return anyIn(password, lower) && anyIn(password, upper) &&
           anyIn(password, digits) && anyIn(password, specials) &&
           neighborsOk(password);
}

/* The buffer holds exactly the characters, with no terminator: the IPMI
 * response fields are fixed at 16 bytes, which the generated strings fill
 * completely. The size checks in userNameOk() and passwordOk() enforce this,
 * and a stray null byte is not in any allowed set. */
std::string_view textOf(const ipmi::SecureBuffer& buffer)
{
    return {reinterpret_cast<const char*>(buffer.data()), buffer.size()};
}

TEST(BootstrapCredentialsTest, UserNamesMeetThePolicy)
{
    for (int i = 0; i < iterations; ++i)
    {
        auto name = createUserName(nameLength);
        if (!name)
        {
            FAIL() << "iteration " << i;
        }
        const auto text = textOf(*name);
        ASSERT_TRUE(userNameOk(text))
            << "iteration " << i << ": " << std::string(text);
    }
}

TEST(BootstrapCredentialsTest, PasswordsMeetThePolicy)
{
    for (int i = 0; i < iterations; ++i)
    {
        auto password = createPassword(passwordLength);
        if (!password)
        {
            FAIL() << "iteration " << i;
        }
        const auto text = textOf(*password);
        ASSERT_TRUE(passwordOk(text))
            << "iteration " << i << ": " << std::string(text);
    }
}

/* The shortest lengths leave the least room, so they get checked as well */
TEST(BootstrapCredentialsTest, ShortestSupportedLengthsMeetThePolicy)
{
    for (int i = 0; i < 10000; ++i)
    {
        auto name = createUserName(4);
        if (!name)
        {
            FAIL();
        }
        const auto nameText = textOf(*name);
        ASSERT_EQ(nameText.size(), 4U);
        ASSERT_TRUE(contains(lower, nameText[0]) ||
                    contains(upper, nameText[0]));
        ASSERT_TRUE(anyIn(nameText, lower) && anyIn(nameText, upper) &&
                    anyIn(nameText, digits) && neighborsOk(nameText))
            << std::string(nameText);

        auto password = createPassword(5);
        if (!password)
        {
            FAIL();
        }
        const auto passwordText = textOf(*password);
        ASSERT_EQ(passwordText.size(), 5U);
        ASSERT_TRUE(anyIn(passwordText, lower) && anyIn(passwordText, upper) &&
                    anyIn(passwordText, digits) &&
                    anyIn(passwordText, specials) && neighborsOk(passwordText))
            << std::string(passwordText);
    }
}

TEST(BootstrapCredentialsTest, RejectsUnsupportedLengths)
{
    EXPECT_FALSE(createUserName(0));
    EXPECT_FALSE(createPassword(0));
    /* fewer positions than required character kinds */
    EXPECT_FALSE(createUserName(3));
    EXPECT_FALSE(createPassword(4));
    /* longer than the generator buffers */
    EXPECT_FALSE(createUserName(33));
    EXPECT_FALSE(createPassword(33));
}

/* Required characters land anywhere but position 0, and position 0 stays
 * possible for the free draw, so a fixed or biased slot choice would show up
 * as a position that never hosts a special character. */
TEST(BootstrapCredentialsTest, SpecialCharacterPositionsVary)
{
    std::set<size_t> seen;
    for (int i = 0; i < iterations; ++i)
    {
        auto password = createPassword(passwordLength);
        if (!password)
        {
            FAIL();
        }
        const auto text = textOf(*password);
        for (size_t pos = 0; pos < text.size(); ++pos)
        {
            if (contains(specials, text[pos]))
            {
                seen.insert(pos);
            }
        }
    }
    EXPECT_EQ(seen.size(), passwordLength);
}

TEST(BootstrapCredentialsTest, PasswordsDoNotRepeat)
{
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i)
    {
        auto password = createPassword(passwordLength);
        if (!password)
        {
            FAIL();
        }
        EXPECT_TRUE(seen.insert(std::string(textOf(*password))).second);
    }
}

TEST(BootstrapCredentialsTest, ByteSourceRejectsBadBounds)
{
    ByteSource source;
    EXPECT_EQ(source.next(0), -1);
    EXPECT_EQ(source.next(257), -1);
}

TEST(BootstrapCredentialsTest, ByteSourceStaysInRangeAndCoversIt)
{
    ByteSource source;
    for (size_t n : {1U, 2U, 3U, 10U, 26U, 29U, 89U, 91U, 255U, 256U})
    {
        std::set<int> seen;
        for (int i = 0; i < 200000; ++i)
        {
            const int value = source.next(n);
            ASSERT_GE(value, 0) << "n=" << n;
            ASSERT_LT(static_cast<size_t>(value), n) << "n=" << n;
            seen.insert(value);
        }
        EXPECT_EQ(seen.size(), n) << "n=" << n;
    }
}

/* Chi-square statistic of the draws against the uniform distribution. Reducing
 * a byte with % n and no rejection skews the low indices by 4% to 50% for
 * these n, which gives a statistic from about 370 (n = 10) to about 19000
 * (n = 91) at this many draws. The bound is far above anything a fair source
 * produces (the statistic averages n - 1), so the test cannot flake. The n
 * are the set sizes the generator draws from: digits, letters of one case,
 * specials, user name characters and password characters with and without
 * two of them excluded. */
TEST(BootstrapCredentialsTest, ByteSourceIsUniform)
{
    constexpr int draws = 1000000;
    ByteSource source;
    for (size_t n : {10U, 26U, 29U, 62U, 89U, 91U})
    {
        std::vector<int> counts(n, 0);
        for (int i = 0; i < draws; ++i)
        {
            const int value = source.next(n);
            ASSERT_GE(value, 0);
            ++counts[static_cast<size_t>(value)];
        }

        const double expected = static_cast<double>(draws) / n;
        double chiSquare = 0;
        for (int count : counts)
        {
            const double deviation = count - expected;
            chiSquare += deviation * deviation / expected;
        }
        const double degrees = static_cast<double>(n - 1);
        EXPECT_LT(chiSquare, 5 * degrees + 50) << "n=" << n;
    }
}

/* Chi-square statistic of per-character counts against a uniform spread over
 * the given set. Counts of characters outside the set are ignored. */
double chiSquareOver(std::string_view set, const std::map<char, int>& counts)
{
    double total = 0;
    for (char c : set)
    {
        auto it = counts.find(c);
        total += it == counts.end() ? 0 : it->second;
    }
    const double expected = total / static_cast<double>(set.size());
    double chiSquare = 0;
    for (char c : set)
    {
        auto it = counts.find(c);
        const double deviation =
            (it == counts.end() ? 0 : it->second) - expected;
        chiSquare += deviation * deviation / expected;
    }
    return chiSquare;
}

constexpr int nameSamples = 200000;

/* Position 0 is only ever a letter, drawn from all 52 of them, and nothing
 * but the first draw has an influence on it, so it is exactly uniform. */
TEST(BootstrapCredentialsTest, UserNameFirstCharIsUniform)
{
    std::map<char, int> counts;
    for (int i = 0; i < nameSamples; ++i)
    {
        auto name = createUserName(nameLength);
        if (!name)
        {
            FAIL();
        }
        ++counts[textOf(*name)[0]];
    }
    const std::string letters = std::string(lower) + std::string(upper);
    EXPECT_EQ(counts.size(), letters.size());
    EXPECT_LT(chiSquareOver(letters, counts), 5 * 51.0 + 50);
}

/* Positions 1..15 mix free draws over all 62 characters with the forced
 * lowercase, uppercase and digit slots, so they are not uniform over 62. Both
 * kinds of draw are uniform inside a class though, so each class must be
 * uniform over its own members. */
TEST(BootstrapCredentialsTest, UserNameInnerCharsAreUniformWithinClass)
{
    std::map<char, int> counts;
    for (int i = 0; i < nameSamples; ++i)
    {
        auto name = createUserName(nameLength);
        if (!name)
        {
            FAIL();
        }
        const auto text = textOf(*name);
        for (size_t pos = 1; pos < text.size(); ++pos)
        {
            ++counts[text[pos]];
        }
    }
    EXPECT_LT(chiSquareOver(lower, counts), 5 * 25.0 + 50);
    EXPECT_LT(chiSquareOver(upper, counts), 5 * 25.0 + 50);
    EXPECT_LT(chiSquareOver(digits, counts), 5 * 9.0 + 50);
}

/* The class of a character at positions 1..15 follows the mix of free and
 * forced draws: each required class takes a given position with probability
 * 1/15, and any other draw falls in the class in proportion to its size. A
 * fixed or missing slot choice moves these shares by several percent. The
 * no-repeat rule nudges them a little, so the bound is loose. */
TEST(BootstrapCredentialsTest, UserNameClassMixMatchesTheDraws)
{
    constexpr double freeShare = (nameLength - 1.0 - 3.0) / (nameLength - 1.0);
    constexpr double forcedShare = 1.0 / (nameLength - 1.0);
    constexpr double setTotal = 62.0;

    double lowerCount = 0, upperCount = 0, digitCount = 0, total = 0;
    for (int i = 0; i < nameSamples; ++i)
    {
        auto name = createUserName(nameLength);
        if (!name)
        {
            FAIL();
        }
        const auto text = textOf(*name);
        for (size_t pos = 1; pos < text.size(); ++pos)
        {
            lowerCount += contains(lower, text[pos]);
            upperCount += contains(upper, text[pos]);
            digitCount += contains(digits, text[pos]);
            ++total;
        }
    }
    EXPECT_NEAR(lowerCount / total,
                freeShare * lower.size() / setTotal + forcedShare, 0.01);
    EXPECT_NEAR(upperCount / total,
                freeShare * upper.size() / setTotal + forcedShare, 0.01);
    EXPECT_NEAR(digitCount / total,
                freeShare * digits.size() / setTotal + forcedShare, 0.01);
}

/* Beyond the fact that every position can hold a special, the chance has to
 * be flat: position 0 only gets free draws, positions 1..15 add a forced slot
 * with probability 1/15 */
TEST(BootstrapCredentialsTest, PasswordSpecialRateIsFlatAcrossPositions)
{
    /* specials are 29 of the 91 characters a password draws from */
    constexpr double setShare = 29.0 / 91.0;
    constexpr double freeShare =
        (passwordLength - 1.0 - 4.0) / (passwordLength - 1.0);
    constexpr double forcedShare = 1.0 / (passwordLength - 1.0);
    static_assert(29 == specials.size());

    std::vector<double> hits(passwordLength, 0);
    for (int i = 0; i < nameSamples; ++i)
    {
        auto password = createPassword(passwordLength);
        if (!password)
        {
            FAIL();
        }
        const auto text = textOf(*password);
        for (size_t pos = 0; pos < text.size(); ++pos)
        {
            hits[pos] += contains(specials, text[pos]);
        }
    }
    EXPECT_NEAR(hits[0] / nameSamples, setShare, 0.02);
    for (size_t pos = 1; pos < passwordLength; ++pos)
    {
        EXPECT_NEAR(hits[pos] / nameSamples, freeShare * setShare + forcedShare,
                    0.02)
            << "pos=" << pos;
    }
}

} // namespace
