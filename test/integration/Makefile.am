top_integbuilddir = $(top_builddir)/test/integration
top_mockgendir = $(top_integbuilddir)/xyz/openbmc_project


AM_LDFLAGS = \
	$(GTEST_LIBS) \
	$(GMOCK_LIBS) \
	-lgmock_main \
	$(OESDK_TESTCASE_FLAGS) \
	$(SDBUSPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(CODE_COVERAGE_LIBS)


check_PROGRAMS = itest_app itest_sensor itest_transport

TESTS = $(check_PROGRAMS)

BUILT_SOURCES = $(dbus_interface_generated_files)

dbus_interface_generated_files = \
	$(top_mockgendir)/Control/Security/RestrictionMode/server.cpp \
	$(top_mockgendir)/Sensor/Value/server.cpp \
	$(top_mockgendir)/State/BMC/server.cpp \
	$(top_mockgendir)/User/Manager/server.cpp \
	$(top_mockgendir)/User/Attributes/server.cpp \
	$(top_mockgendir)/Network/SystemConfiguration/server.cpp \
	$(top_mockgendir)/Network/EthernetInterface/server.cpp \
	$(top_mockgendir)/Network/MACAddress/server.cpp \
	$(top_mockgendir)/Network/Neighbor/CreateStatic/server.cpp \
	$(top_mockgendir)/Network/VLAN/Create/server.cpp \
	$(top_mockgendir)/Network/IP/Create/server.cpp

$(dbus_interface_generated_files):
	sdbus++-gendir --tool sdbus++ --output $(top_integbuilddir) --gen-mocks xyz

integration_test_common_files = \
	common/mapperd_manager.cpp \
	common/integration_test.cpp \
	common/services/sensor_server.cpp \
	common/services/restriction_mode.cpp \
	common/services/user_manager.cpp \
	common/services/bmc_state.cpp \
	common/services/networkd.cpp

itest_app_SOURCES = \
	$(dbus_interface_generated_files) \
	$(integration_test_common_files) \
	ipmid_test.cpp \
	itest_app.cpp

itest_sensor_SOURCES = \
	$(dbus_interface_generated_files) \
	$(integration_test_common_files) \
	ipmid_test.cpp \
	itest_sensor.cpp

itest_transport_SOURCES = \
	$(dbus_interface_generated_files) \
	$(integration_test_common_files) \
	ipmid_test.cpp \
	itest_transport.cpp

CLEANFILES = \
	$(dbus_interface_generated_files)
