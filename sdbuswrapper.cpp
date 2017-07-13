#include "sdbuswrapper.h"

int SdBusWrapperImpl::sd_bus_message_new_method_call(sd_bus* bus,
                                          sd_bus_message** m,
                                          const char* interface_bus,
                                          const char* interface_path,
                                          const char* interface_type,
                                          const char* interface_operation) {
    return ::sd_bus_message_new_method_call(bus, m, interface_bus,
                                          interface_path, interface_type,
                                          interface_operation);
}

int SdBusWrapperImpl::sd_bus_call(sd_bus *bus, sd_bus_message *m, uint64_t usec,
                       sd_bus_error *ret_error, sd_bus_message **reply) {
    return ::sd_bus_call(bus, m, usec, ret_error, reply);
}

int SdBusWrapperImpl::sd_bus_call_method(sd_bus *bus, const char* destination,
                              const char* path, const char* interface,
                              const char* member, sd_bus_error *error,
                              sd_bus_message **reply, const char* types,
                              const char* a1){
    return ::sd_bus_call_method(bus, destination, path, interface, member,
                              error, reply, types, a1);
}

int SdBusWrapperImpl::sd_bus_call_method(sd_bus *bus, const char* destination,
                              const char* path, const char* interface,
                              const char* member, sd_bus_error *error,
                              sd_bus_message **reply, const char* types,
                              const char* a1, const char a2){
    return ::sd_bus_call_method(bus, destination, path, interface, member,
                              error, reply, types, a1, a2);
}

int SdBusWrapperImpl::sd_bus_get_property(sd_bus *bus, const char *destination,
                               const char *path, const char *interface,
                               const char *member, sd_bus_error *ret_error,
                               sd_bus_message **reply, const char *type) {
    return ::sd_bus_get_property(bus, destination, path, interface, member,
                               ret_error, reply, type);
}

int SdBusWrapperImpl::sd_bus_message_append(sd_bus_message *m, const char *types,
                                        const char *a1)
{
    return ::sd_bus_message_append(m, types, a1);
}

int SdBusWrapperImpl::sd_bus_message_append(sd_bus_message *m, const char *types,
                                        const char *a1, const char *a2)
{
    return ::sd_bus_message_append(m, types, a1, a2);
}

int SdBusWrapperImpl::sd_bus_message_append(sd_bus_message *m, const char *types,
                                        const char *a1, const char a2)
{
    return ::sd_bus_message_append(m, types, a1, a2);
}

int SdBusWrapperImpl::sd_bus_message_read(sd_bus_message *m, const char *types, char **a1)
{
    return ::sd_bus_message_read(m, types, a1);
}

int SdBusWrapperImpl::sd_bus_message_read(sd_bus_message *m, const char *types, int *a1)
{
    return ::sd_bus_message_read(m, types, a1);
}

int SdBusWrapperImpl::sd_bus_message_read(sd_bus_message *m, const char *types, const char *a1, char **a2)
{
    return ::sd_bus_message_read(m, types, a1, a2);
}

int SdBusWrapperImpl::sd_bus_message_read(sd_bus_message *m, const char *types, char **a1, char **a2)
{
    return ::sd_bus_message_read(m, types, a1, a2);
}

void SdBusWrapperImpl::sd_bus_error_free(sd_bus_error *e)
{
    ::sd_bus_error_free(e);
}

sd_bus_message* SdBusWrapperImpl::sd_bus_message_unref(sd_bus_message *m)
{
    return ::sd_bus_message_unref(m);
}

int SdBusWrapperImpl::sd_bus_get_property_trivial(sd_bus *bus, const char *destination,
                                const char *path, const char *interface,
                                const char *member, sd_bus_error *ret_error,
                                char type, void *ret_ptr)
{
    return ::sd_bus_get_property_trivial(bus, destination, path, interface, member,
                                         ret_error, type, ret_ptr);
}

int SdBusWrapperImpl::sd_bus_get_property_string(sd_bus *bus, const char *destination,
                               const char *path, const char *interface,
                               const char *member, sd_bus_error *ret_error,
                               char **ret) /* free the result! */
{
    return ::sd_bus_get_property_string(bus, destination, path, interface, member,
                                        ret_error, ret);
}
