#ifndef DBUS_IPML_H_
#define DBUS_IPML_H_

#include <sstream>
#include <string>
#include <mapper.h>
#include <systemd/sd-bus.h>

#include "dbus.hpp"

namespace ipmid
{

class DBusMessageOperationsImpl : public DBusMessageOperations
{
    public:
        int sd_bus_message_append_basic(sd_bus_message* message,
                                        char type,
                                        const void* value) const override
        {
            return ::sd_bus_message_append_basic(message, type, value);
        }

        int sd_bus_message_append_array(sd_bus_message* message,
                                        char type,
                                        const void* array,
                                        size_t size) const override
        {
            return ::sd_bus_message_append_array(message, type, array, size);
        }

        int sd_bus_message_read_basic(sd_bus_message* message,
                                      char type,
                                      void* value) const override
        {
            return ::sd_bus_message_read_basic(message, type, value);
        }

        int sd_bus_message_read_array(sd_bus_message* message,
                                      char type,
                                      const void** array,
                                      size_t* size) const override
        {
            return ::sd_bus_message_read_array(message, type, array, size);
        }

        int sd_bus_message_enter_container(sd_bus_message* message,
                                           char type,
                                           const char* contents) const override
        {
            return ::sd_bus_message_enter_container(message, type, contents);
        }

        const char* sd_bus_message_get_sender(sd_bus_message* message) const override
        {
            return ::sd_bus_message_get_sender(message);
        }

        const char* sd_bus_message_get_path(sd_bus_message* message) const override
        {
            return ::sd_bus_message_get_path(message);
        }
};

class DBusBusOperationsImpl : public DBusBusOperations
{
    public:
        int sd_bus_open_system(sd_bus** bus) const override
        {
            return ::sd_bus_open_system(bus);
        }

        sd_bus* sd_bus_unref(sd_bus* bus) const override
        {
            return ::sd_bus_unref(bus);
        }

        sd_bus_slot* sd_bus_slot_unref(sd_bus_slot* slot) const override
        {
            return ::sd_bus_slot_unref(slot);
        }

        int mapper_get_service(sd_bus* bus, const char* path,
                               char** dest) const override
        {
            return ::mapper_get_service(bus, path, dest);
        }

        int sd_bus_message_new_method_call(sd_bus* bus,
                                           sd_bus_message** message,
                                           const char* destination,
                                           const char* path,
                                           const char* interface,
                                           const char* member) const override
        {
            return ::sd_bus_message_new_method_call(bus,
                                                    message,
                                                    destination,
                                                    path,
                                                    interface,
                                                    member);
        }

        int sd_bus_call(sd_bus* bus,
                        sd_bus_message* message,
                        uint64_t usec,
                        void* error,
                        sd_bus_message** reply) const override
        {
            return ::sd_bus_call(bus, message, usec, reinterpret_cast<sd_bus_error*>(error),
                                 reply);
        }

        void sd_bus_error_free(void* error) const override
        {
            return ::sd_bus_error_free(reinterpret_cast<sd_bus_error*>(error));
        }

        sd_bus_message* sd_bus_message_unref(sd_bus_message* message) const override
        {
            return ::sd_bus_message_unref(message);
        }

        int sd_bus_add_match(sd_bus* bus,
                             sd_bus_slot** slot,
                             const char* match,
                             SdBusMessageHandlerT callback,
                             void* userdata) const override
        {
            return ::sd_bus_add_match(bus,
                                      slot,
                                      match,
                                      reinterpret_cast<sd_bus_message_handler_t>(callback),
                                      userdata);
        }

        int sd_bus_process(sd_bus* bus, sd_bus_message** message) const override
        {
            return ::sd_bus_process(bus, message);
        }

        int sd_bus_wait(sd_bus* bus, uint64_t timeout_usec) const override
        {
            return ::sd_bus_wait(bus, timeout_usec);
        }

        DBusErrorUniquePtr MakeError() const override
        {
            sd_bus_error* error =
                    reinterpret_cast<sd_bus_error*>(malloc(sizeof(sd_bus_error)));
            *error = SD_BUS_ERROR_NULL;
            return DBusErrorUniquePtr(reinterpret_cast<DBusError*>(error));
        }

        std::string DBusErrorToString(const DBusError& error_stand_in) const override
        {
            const sd_bus_error& error =
                    reinterpret_cast<const sd_bus_error&>(error_stand_in);
            std::stringstream ss;
            ss << error.name
               << ", "
               << error.message;
            return ss.str();
        }
};

} // namespace ipmid

#endif // DBUS_IPML_H_
