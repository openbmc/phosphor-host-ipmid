#include <algorithm>
#include <sdbusplus/server.hpp>
#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/Ipmi/Internal/SoftPowerOff/server.hpp>

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

SoftPowerOff::SoftPowerOff(bus::bus& bus, const char* path)
        : _xyz_openbmc_project_Ipmi_Internal_SoftPowerOff_interface(
                bus, path, _interface, _vtable, this)
{
}



auto SoftPowerOff::responseReceived() const ->
        HostResponse
{
    return _responseReceived;
}

int SoftPowerOff::_callback_get_ResponseReceived(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* reply, void* context,
        sd_bus_error* error)
{
    using sdbusplus::server::binding::details::convertForMessage;

    try
    {
        auto m = message::message(reply);

        auto o = static_cast<SoftPowerOff*>(context);
        m.append(convertForMessage(o->responseReceived()));
    }
    catch(sdbusplus::internal_exception_t& e)
    {
        sd_bus_error_set_const(error, e.name(), e.description());
        return -EINVAL;
    }

    return true;
}

auto SoftPowerOff::responseReceived(HostResponse value) ->
        HostResponse
{
    if (_responseReceived != value)
    {
        _responseReceived = value;
        _xyz_openbmc_project_Ipmi_Internal_SoftPowerOff_interface.property_changed("ResponseReceived");
    }

    return _responseReceived;
}

int SoftPowerOff::_callback_set_ResponseReceived(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* value, void* context,
        sd_bus_error* error)
{
    try
    {
        auto m = message::message(value);

        auto o = static_cast<SoftPowerOff*>(context);

        std::string v{};
        m.read(v);
        o->responseReceived(convertHostResponseFromString(v));
    }
    catch(sdbusplus::internal_exception_t& e)
    {
        sd_bus_error_set_const(error, e.name(), e.description());
        return -EINVAL;
    }

    return true;
}

namespace details
{
namespace SoftPowerOff
{
static const auto _property_ResponseReceived =
    utility::tuple_to_array(message::types::type_id<
            std::string>());
}
}


namespace
{
/** String to enum mapping for SoftPowerOff::HostResponse */
static const std::tuple<const char*, SoftPowerOff::HostResponse> mappingSoftPowerOffHostResponse[] =
        {
            std::make_tuple( "xyz.openbmc_project.Ipmi.Internal.SoftPowerOff.HostResponse.NotApplicable",                 SoftPowerOff::HostResponse::NotApplicable ),
            std::make_tuple( "xyz.openbmc_project.Ipmi.Internal.SoftPowerOff.HostResponse.SoftOffReceived",                 SoftPowerOff::HostResponse::SoftOffReceived ),
            std::make_tuple( "xyz.openbmc_project.Ipmi.Internal.SoftPowerOff.HostResponse.HostShutdown",                 SoftPowerOff::HostResponse::HostShutdown ),
        };

} // anonymous namespace

auto SoftPowerOff::convertHostResponseFromString(std::string& s) ->
        HostResponse
{
    auto i = std::find_if(
            std::begin(mappingSoftPowerOffHostResponse),
            std::end(mappingSoftPowerOffHostResponse),
            [&s](auto& e){ return 0 == strcmp(s.c_str(), std::get<0>(e)); } );
    if (std::end(mappingSoftPowerOffHostResponse) == i)
    {
        throw sdbusplus::exception::InvalidEnumString();
    }
    else
    {
        return std::get<1>(*i);
    }
}

std::string convertForMessage(SoftPowerOff::HostResponse v)
{
    auto i = std::find_if(
            std::begin(mappingSoftPowerOffHostResponse),
            std::end(mappingSoftPowerOffHostResponse),
            [v](auto& e){ return v == std::get<1>(e); });
    return std::get<0>(*i);
}

const vtable::vtable_t SoftPowerOff::_vtable[] = {
    vtable::start(),
    vtable::property("ResponseReceived",
                     details::SoftPowerOff::_property_ResponseReceived
                        .data(),
                     _callback_get_ResponseReceived,
                     _callback_set_ResponseReceived,
                     vtable::property_::emits_change),
    vtable::end()
};

} // namespace server
} // namespace Internal
} // namespace Ipmi
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

