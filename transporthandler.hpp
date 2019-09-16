#pragma once

#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/message/types.hpp>

namespace ipmi::transport
{
/** @brief IPMI LAN Parameters */
enum class LanParam : uint8_t
{
    SetStatus = 0,
    AuthSupport = 1,
    AuthEnables = 2,
    IP = 3,
    IPSrc = 4,
    MAC = 5,
    SubnetMask = 6,
    Gateway1 = 12,
    VLANId = 20,
    CiphersuiteSupport = 22,
    CiphersuiteEntries = 23,
    oemCmd192 = 192,
    oemCmd193 = 193,
    oemCmd194 = 194,
    oemCmd195 = 195,
    oemCmd196 = 196,
    oemCmd197 = 197,
    oemCmd198 = 198,
    oemCmd199 = 199,
    oemCmd200 = 200,
    oemCmd201 = 201,
    oemCmd202 = 202,
    oemCmd203 = 203,
    oemCmd204 = 204,
    oemCmd205 = 205,
    oemCmd206 = 206,
    oemCmd207 = 207,
    oemCmd208 = 208,
    oemCmd209 = 209,
    oemCmd210 = 210,
    oemCmd211 = 211,
    oemCmd212 = 212,
    oemCmd213 = 213,
    oemCmd214 = 214,
    oemCmd215 = 215,
    oemCmd216 = 216,
    oemCmd217 = 217,
    oemCmd218 = 218,
    oemCmd219 = 219,
    oemCmd220 = 220,
    oemCmd221 = 221,
    oemCmd222 = 222,
    oemCmd223 = 223,
    oemCmd224 = 224,
    oemCmd225 = 225,
    oemCmd226 = 226,
    oemCmd227 = 227,
    oemCmd228 = 228,
    oemCmd229 = 229,
    oemCmd230 = 230,
    oemCmd231 = 231,
    oemCmd232 = 232,
    oemCmd233 = 233,
    oemCmd234 = 234,
    oemCmd235 = 235,
    oemCmd236 = 236,
    oemCmd237 = 237,
    oemCmd238 = 238,
    oemCmd239 = 239,
    oemCmd240 = 240,
    oemCmd241 = 241,
    oemCmd242 = 242,
    oemCmd243 = 243,
    oemCmd244 = 244,
    oemCmd245 = 245,
    oemCmd246 = 246,
    oemCmd247 = 247,
    oemCmd248 = 248,
    oemCmd249 = 249,
    oemCmd250 = 250,
    oemCmd251 = 251,
    oemCmd252 = 252,
    oemCmd253 = 253,
    oemCmd254 = 254,
    oemCmd255 = 255,
};

// LAN Handler specific response codes
constexpr Cc ccParamNotSupported = 0x80;
constexpr Cc ccParamSetLocked = 0x81;
constexpr Cc ccParamReadOnly = 0x82;

} // namespace ipmi::transport
