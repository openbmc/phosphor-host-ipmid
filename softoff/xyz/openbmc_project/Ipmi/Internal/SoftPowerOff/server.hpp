#pragma once
#include <tuple>
#include <systemd/sd-bus.h>
#include <sdbusplus/server.hpp>

namespace sdbusplus
{
namespace xyz
{
namespace openbmc_project
{
namespace Ipmi
{
namespace Internal
{
namespace server
{

class SoftPowerOff
{
    public:
        /* Define all of the basic class operations:
         *     Not allowed:
         *         - Default constructor to avoid nullptrs.
         *         - Copy operations due to internal unique_ptr.
         *         - Move operations due to 'this' being registered as the
         *           'context' with sdbus.
         *     Allowed:
         *         - Destructor.
         */
        SoftPowerOff() = delete;
        SoftPowerOff(const SoftPowerOff&) = delete;
        SoftPowerOff& operator=(const SoftPowerOff&) = delete;
        SoftPowerOff(SoftPowerOff&&) = delete;
        SoftPowerOff& operator=(SoftPowerOff&&) = delete;
        virtual ~SoftPowerOff() = default;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         */
        SoftPowerOff(bus::bus& bus, const char* path);

        enum class HostResponse
        {
            NotApplicable,
            SoftOffReceived,
            HostShutdown,
        };



        /** Get value of ResponseReceived */
        virtual HostResponse responseReceived() const;
        /** Set value of ResponseReceived */
        virtual HostResponse responseReceived(HostResponse value);

    /** @brief Convert a string to an appropriate enum value.
     *  @param[in] s - The string to convert in the form of
     *                 "xyz.openbmc_project.Ipmi.Internal.SoftPowerOff.<value name>"
     *  @return - The enum value.
     */
    static HostResponse convertHostResponseFromString(std::string& s);

    private:

        /** @brief sd-bus callback for get-property 'ResponseReceived' */
        static int _callback_get_ResponseReceived(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'ResponseReceived' */
        static int _callback_set_ResponseReceived(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);


        static constexpr auto _interface = "xyz.openbmc_project.Ipmi.Internal.SoftPowerOff";
        static const vtable::vtable_t _vtable[];
        sdbusplus::server::interface::interface
                _xyz_openbmc_project_Ipmi_Internal_SoftPowerOff_interface;

        HostResponse _responseReceived = HostResponse::NotApplicable;

};

/* Specialization of sdbusplus::server::bindings::details::convertForMessage
 * for enum-type SoftPowerOff::HostResponse.
 *
 * This converts from the enum to a constant c-string representing the enum.
 *
 * @param[in] e - Enum value to convert.
 * @return C-string representing the name for the enum value.
 */
std::string convertForMessage(SoftPowerOff::HostResponse e);

} // namespace server
} // namespace Internal
} // namespace Ipmi
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

