#ifndef __HOST_IPMI_SDBUS_WRAPPER_H__
#define __HOST_IPMI_SDBUS_WRAPPER_H__

#include <systemd/sd-bus.h>
/**
 * Wrap sdbus calls for easier testing
 */

class SdBusWrapper
{
  public:
    virtual int sd_bus_message_new_method_call(sd_bus *bus,
                                              sd_bus_message **m,
                                              const char* interface_bus,
                                              const char* interface_path,
                                              const char* interface_type,
                                              const char* interface_operation) = 0;

    virtual int sd_bus_call(sd_bus *bus, sd_bus_message *m, uint64_t usec,
                           sd_bus_error *ret_error, sd_bus_message **reply) = 0;

    virtual int sd_bus_call_method(sd_bus *bus, const char* destination,
                                  const char* path, const char* interface,
                                  const char* member, sd_bus_error *error,
                                  sd_bus_message **reply, const char* types,
                                  const char* a1) = 0;

    virtual int sd_bus_call_method(sd_bus *bus, const char* destination,
                                  const char* path, const char* interface,
                                  const char* member, sd_bus_error *error,
                                  sd_bus_message **reply, const char* types,
                                  const char* a1, const char a2) = 0;

    virtual int sd_bus_get_property(sd_bus *bus, const char *destination,
                                   const char *path, const char *interface,
                                   const char *member, sd_bus_error *ret_error,
                                   sd_bus_message **reply, const char *type) = 0;

    virtual int sd_bus_message_append(sd_bus_message *m, const char *types, const char *a1) = 0;
    virtual int sd_bus_message_append(sd_bus_message *m, const char *types, const char *a1,
                              const char *a2) = 0;
    virtual int sd_bus_message_append(sd_bus_message *m, const char *types, const char *a1,
                              const char a2) = 0;

    virtual int sd_bus_message_read(sd_bus_message *m, const char *types, char **a1) = 0;
    virtual int sd_bus_message_read(sd_bus_message *m, const char *types, int *a1) = 0;
    virtual int sd_bus_message_read(sd_bus_message *m, const char *types, const char *a1, char **a2) = 0;
    virtual int sd_bus_message_read(sd_bus_message *m, const char *types, char **a1, char **a2) = 0;

    virtual void sd_bus_error_free(sd_bus_error *e) = 0;

    virtual sd_bus_message* sd_bus_message_unref(sd_bus_message *m) = 0;

    virtual int sd_bus_get_property_trivial(sd_bus *bus, const char *destination,
                                    const char *path, const char *interface,
                                    const char *member, sd_bus_error *ret_error,
                                    char type, void *ret_ptr) = 0;

    virtual int sd_bus_get_property_string(sd_bus *bus, const char *destination,
                                   const char *path, const char *interface,
                                   const char *member, sd_bus_error *ret_error,
                                   char **ret) = 0; /* free the result! */
};

class SdBusWrapperImpl : public SdBusWrapper
{
  public:
    int sd_bus_message_new_method_call(sd_bus *bus,
                                              sd_bus_message **m,
                                              const char* interface_bus,
                                              const char* interface_path,
                                              const char* interface_type,
                                              const char* interface_operation);

    int sd_bus_call(sd_bus *bus, sd_bus_message *m, uint64_t usec,
                           sd_bus_error *ret_error, sd_bus_message **reply);

    int sd_bus_call_method(sd_bus *bus, const char* destination,
                                  const char* path, const char* interface,
                                  const char* member, sd_bus_error *error,
                                  sd_bus_message **reply, const char* types,
                                  const char* a1);

    int sd_bus_call_method(sd_bus *bus, const char* destination,
                                  const char* path, const char* interface,
                                  const char* member, sd_bus_error *error,
                                  sd_bus_message **reply, const char* types,
                                  const char* a1, const char a2);

    int sd_bus_get_property(sd_bus *bus, const char *destination,
                                   const char *path, const char *interface,
                                   const char *member, sd_bus_error *ret_error,
                                   sd_bus_message **reply, const char *type);

    int sd_bus_message_append(sd_bus_message *m, const char *types, const char *a1);
    int sd_bus_message_append(sd_bus_message *m, const char *types, const char *a1,
                              const char *a2);
    int sd_bus_message_append(sd_bus_message *m, const char *types, const char *a1,
                              const char a2);

    int sd_bus_message_read(sd_bus_message *m, const char *types, char **a1);
    int sd_bus_message_read(sd_bus_message *m, const char *types, int *a1);
    int sd_bus_message_read(sd_bus_message *m, const char *types, const char *a1, char **a2);
    int sd_bus_message_read(sd_bus_message *m, const char *types, char **a1, char **a2);

    void sd_bus_error_free(sd_bus_error *e);

    sd_bus_message* sd_bus_message_unref(sd_bus_message *m);

    int sd_bus_get_property_trivial(sd_bus *bus, const char *destination,
                                    const char *path, const char *interface,
                                    const char *member, sd_bus_error *ret_error,
                                    char type, void *ret_ptr);

    int sd_bus_get_property_string(sd_bus *bus, const char *destination,
                                   const char *path, const char *interface,
                                   const char *member, sd_bus_error *ret_error,
                                   char **ret); /* free the result! */
};

#endif
