nobase_include_HEADERS = \
	ipmid/api.hpp \
	ipmid/handler.hpp \
	ipmid/message.hpp \
	ipmid/message/pack.hpp \
	ipmid/message/types.hpp \
	ipmid/message/unpack.hpp \
	ipmid/registration.hpp \
	ipmid/api.h \
	ipmid/iana.hpp \
	ipmid/oemopenbmc.hpp \
	ipmid/oemrouter.hpp \
	ipmid-host/cmd.hpp \
	ipmid-host/cmd-utils.hpp

# Eventually we will split <ipmid/*> and <host-ipmid/*> headers
# For now they will be the same during migration
install-data-local:
	$(MKDIR_P) $(DESTDIR)$(includedir)/host-ipmid
	$(LN_S) ../ipmid/iana.hpp $(DESTDIR)$(includedir)/host-ipmid/iana.hpp
	$(LN_S) ../ipmid/api.h $(DESTDIR)$(includedir)/host-ipmid/ipmid-api.h
	$(LN_S) ../ipmid/oemopenbmc.hpp $(DESTDIR)$(includedir)/host-ipmid/oemopenbmc.hpp
	$(LN_S) ../ipmid/oemrouter.hpp $(DESTDIR)$(includedir)/host-ipmid/oemrouter.hpp
	$(LN_S) ../ipmid-host/cmd.hpp $(DESTDIR)$(includedir)/host-ipmid/ipmid-host-cmd.hpp
	$(LN_S) ../ipmid-host/cmd-utils.hpp $(DESTDIR)$(includedir)/host-ipmid/ipmid-host-cmd-utils.hpp

