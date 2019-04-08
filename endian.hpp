#pragma once

#include <endian.h>
#include <stdint.h>

#include <climits>

namespace endian
{
namespace details
{
// These two template functions convert IPMI data buffer to/from an
// arbitrary length integer. These can be used for 24-bit numbers,
// where usual integer conversion would fail.

template <typename T>
T from_ipmi(uint8_t* ipmi, size_t bytes)
{
    size_t byte = 0;
    T o;

    // IPMI always has LSB first
    for (o = byte = 0; byte < bytes && byte < sizeof(T); ++byte)
    {
        o |= ipmi[byte] << (CHAR_BIT * byte);
    }

    return o;
}

template <typename T>
void to_ipmi(T i, uint8_t* ipmi, size_t bytes)
{
    size_t byte = 0;

    // IPMI always has LSB first
    for (byte = 0; byte < bytes && byte < sizeof(T); ++byte)
    {
        ipmi[byte] = static_cast<uint8_t>((i >> (CHAR_BIT * byte)) & 0xFF);
    }
}

// These are integer conversion templates. Work only for 16- and 32-bit
// integers (well, for 64 too, but they aren't used in IPMI)
template <typename T>
struct convert
{
    static T to_ipmi(T) = delete;
    static T from_ipmi(T) = delete;
    static T to_network(T) = delete;
    static T from_network(T) = delete;
};

template <>
struct convert<uint16_t>
{
    static uint16_t to_ipmi(uint16_t i)
    {
        return htole16(i);
    };
    static uint16_t from_ipmi(uint16_t i)
    {
        return le16toh(i);
    };
    static uint16_t to_network(uint16_t i)
    {
        return htobe16(i);
    };
    static uint16_t from_network(uint16_t i)
    {
        return be16toh(i);
    };
};

template <>
struct convert<uint32_t>
{
    static uint32_t to_ipmi(uint32_t i)
    {
        return htole32(i);
    };
    static uint32_t from_ipmi(uint32_t i)
    {
        return le32toh(i);
    };
    static uint32_t to_network(uint32_t i)
    {
        return htobe32(i);
    };
    static uint32_t from_network(uint32_t i)
    {
        return be32toh(i);
    };
};
} // namespace details

template <typename T>
T to_ipmi(T i)
{
    return details::convert<T>::to_ipmi(i);
}

template <typename T>
void to_ipmi(T i, uint8_t* ipmi, size_t bytes)
{
    return details::to_ipmi<T>(i, ipmi, bytes);
}

template <typename T>
T from_ipmi(T i)
{
    return details::convert<T>::from_ipmi(i);
}

template <typename T>
T from_ipmi(uint8_t* ipmi, size_t bytes)
{
    return details::from_ipmi<T>(ipmi, bytes);
}

template <typename T>
T to_network(T i)
{
    return details::convert<T>::to_network(i);
}

template <typename T>
T from_network(T i)
{
    return details::convert<T>::from_network(i);
}
} // namespace endian
