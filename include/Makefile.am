nobase_include_HEADERS = \
	ipmid/iana.hpp \
	ipmid/api.h \
	ipmid/oemopenbmc.hpp \
	ipmid/oemrouter.hpp \
	ipmid-host/cmd.hpp \
	ipmid-host/cmd-utils.hpp

# Eventually we will split <ipmid/*> and <host-ipmid/*> headers
# For now they will be the same during migration
install-data-local:
	$(MKDIR_P) $(DESTDIR)$(includedir)/host-ipmid
	$(LN_S) ../libipmid/iana.hpp $(DESTDIR)$(includedir)/host-ipmid/iana.hpp
	$(LN_S) ../libipmid/api.h $(DESTDIR)$(includedir)/host-ipmid/ipmid-api.h
	$(LN_S) ../libipmid/oemopenbmc.hpp $(DESTDIR)$(includedir)/host-ipmid/oemopenbmc.hpp
	$(LN_S) ../libipmid/oemrouter.hpp $(DESTDIR)$(includedir)/host-ipmid/oemrouter.hpp
	$(LN_S) ../libipmid-host/cmd.hpp $(DESTDIR)$(includedir)/host-ipmid/ipmid-host-cmd.hpp
	$(LN_S) ../libipmid-host/cmd-utils.hpp $(DESTDIR)$(includedir)/host-ipmid/ipmid-host-cmd-utils.hpp

