#include "user_channel/channel_layer.hpp"
#include "user_channel/cipher_mgmt.hpp"

#include <phosphor-logging/log.hpp>

#include <gtest/gtest.h>

using namespace phosphor::logging;

const std::string csPrivFileName = "cs_privilege_levels.json";
const std::string csPrivDefaultFileName = "cs_privilege_levels_default.json";

namespace ipmi
{
const std::array<std::string, 6> privList = {"priv-reserved", "priv-callback",
                                             "priv-user",     "priv-operator",
                                             "priv-admin",    "priv-oem"};

bool isValidChannel(const uint8_t chNum)
{
    if (chNum > ipmi::maxIpmiChannels)
    {
        log<level::DEBUG>("Invalid channel ID - Out of range");
        return false;
    }
    return true;
}
} // namespace ipmi

// watch for correct singleton behavior
const ipmi::CipherConfig& singletonUnderTest =
    ipmi::getCipherConfigObject(csPrivFileName, csPrivDefaultFileName);

void MakeCipher()
{
    const ipmi::CipherConfig& cipherConfigObj =
        ipmi::getCipherConfigObject(csPrivFileName, csPrivDefaultFileName);
    ASSERT_EQ(&singletonUnderTest, &cipherConfigObj);
}

TEST(ciphersuiteTest, MakeCipherProducesConsistentSingleton)
{
    MakeCipher();
}

// set and get cs privileges and check the value
void setAndGetCSPriv()
{
    uint8_t channel = 0x03;

    std::array<uint8_t, 8> inputBytes = {0x34, 0x43, 0x44, 0x33,
                                         0x44, 0x44, 0x44, 0x44};

    std::array<uint4_t, ipmi::maxCSRecords> requestData;

    constexpr uint8_t requestDataLowerMask = 0x0F;
    constexpr uint8_t requestDataUpperMask = 0xF0;
    constexpr uint8_t requestDataShift = 0x04;

    // converting input byte into nibbles, as setCSPrivilegeLevels expects
    // nibbles as input
    for (size_t index = 0; index < inputBytes.size(); ++index)
    {
        requestData[index * 2] = inputBytes[index] & requestDataLowerMask;

        requestData[index * 2 + 1] =
            (inputBytes[index] & requestDataUpperMask) >> requestDataShift;
    }

    uint8_t resp =
        ipmi::getCipherConfigObject(csPrivFileName, csPrivDefaultFileName)
            .setCSPrivilegeLevels(channel, requestData);

    if (!resp)
    {
        log<level::INFO>("Set privilege is success");
    }
    else if (resp == ipmi::ccInvalidFieldRequest)
    {
        log<level::ERR>("Set CS privileges.. Invalid input");
    }
    else
    {
        log<level::ERR>("Set CS privileges.. Unspecified error");
    }

    std::array<uint4_t, ipmi::maxCSRecords> csPrivilegeLevels;

    uint8_t res =
        ipmi::getCipherConfigObject(csPrivFileName, csPrivDefaultFileName)
            .getCSPrivilegeLevels(channel, csPrivilegeLevels);

    if (!res)
    {
        log<level::INFO>("Get CS privilege is success");
    }
    else if (res == ipmi::ccInvalidFieldRequest)
    {
        log<level::ERR>("Get CS privileges.. Invalid field request");
    }
    else
    {
        log<level::ERR>("Get CS privileges..Unspecified error");
    }
    ASSERT_EQ(requestData, csPrivilegeLevels);
}

TEST(ciphersuiteTest, SetAndGetCSPrivileges)
{
    setAndGetCSPriv();
}

void highestMatchingAlgo()
{
    uint8_t chNum = 0x00;
    uint8_t auth = 0;
    uint8_t integrity = 0;
    uint8_t confidentiality = 0;
    uint8_t csPriv = 0;
    csPriv = ipmi::getCipherConfigObject(csPrivFileName, csPrivDefaultFileName)
                 .getHighestLevelMatchProposedAlgorithm(chNum, auth, integrity,
                                                        confidentiality);

    ASSERT_EQ(csPriv, 0x04);
}

TEST(ciphersuiteTest, highestMatchingAlgo)
{
    highestMatchingAlgo();
}
