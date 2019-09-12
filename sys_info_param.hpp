#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>

// For EFI based system, 256 bytes is recommended.
static constexpr size_t maxBytesPerParameter = 256;

struct IpmiSysInfo
{
    uint8_t encoding;
    size_t stringLen;
    std::array<uint8_t, maxBytesPerParameter> stringDataN;
};

/**
 * Key-value store for string-type system info parameters.
 */
class SysInfoParamStoreIntf
{
  public:
    virtual ~SysInfoParamStoreIntf()
    {
    }

    /**
     * Returns true if parameter is found. If and only if s is non-null,
     * invokes the parameter's callback and writes the value.
     *
     * @param[in] paramSelector - the key to lookup.
     * @return tuple of bool and string, true if parameter is found and
     * string set accordingly.
     */
    virtual std::optional<IpmiSysInfo> lookup(uint8_t paramSelector) const = 0;

    /**
     * Update a parameter by its code with a string value.
     *
     * @param[in] paramSelector - the key to update.
     * @param[in] s - the value to set.
     * @param[in] isNonVolatile - if data should be persistent.
     */
    virtual void update(uint8_t paramSelector, const IpmiSysInfo& s,
                        bool isNonVolatile) = 0;

    /**
     * Update a parameter by its code with a callback that is called to retrieve
     * its value whenever called. Callback must be idempotent, as it may be
     * called multiple times by the host to retrieve the parameter by chunks.
     *
     * @param[in] paramSelector - the key to update.
     * @param[in] callback - the callback to use for parameter retrieval.
     */
    virtual void update(uint8_t paramSelector,
                        const std::function<IpmiSysInfo()>& callback) = 0;

    // TODO: Store "read-only" flag for each parameter.
    // TODO: Function to erase a parameter?
};

/**
 * Implement the system info parameters store as a map of callbacks.
 */
class SysInfoParamStore : public SysInfoParamStoreIntf
{
  public:
    std::optional<IpmiSysInfo> lookup(uint8_t paramSelector) const override;
    void update(uint8_t paramSelector, const IpmiSysInfo& s,
                bool isNonVolatile) override;
    void update(uint8_t paramSelector,
                const std::function<IpmiSysInfo()>& callback) override;
    int restore(uint8_t paramSelector);

  private:
    std::map<uint8_t, std::function<IpmiSysInfo()>> params;
};
