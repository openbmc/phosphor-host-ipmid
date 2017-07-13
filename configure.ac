# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-host-ipmid], [1.0], [https://github.com/openbmc/phosphor-host-ipmid/issues])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# softoff dir specific ones
AC_ARG_ENABLE([softoff],
    AS_HELP_STRING([--enable-softoff], [Builds soft power off])
)
AS_IF([test "x$enable_softoff" != "xno"],
    [AC_PROG_MKDIR_P]
    [AC_CHECK_PROG([DIRNAME], dirname, dirname)]
)

# Checks for libraries.
AC_CHECK_LIB([mapper], [mapper_get_service], ,[AC_MSG_ERROR([Could not find libmapper...openbmc/phosphor-objmgr package required])])
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221], [], [AC_MSG_ERROR(["systemd required and not found"])])
PKG_CHECK_MODULES([PHOSPHOR_LOGGING], [phosphor-logging],, [AC_MSG_ERROR([Could not find phosphor-logging...openbmc/phosphor-logging package required])])
PKG_CHECK_MODULES([PHOSPHOR_DBUS_INTERFACES], [phosphor-dbus-interfaces],, [AC_MSG_ERROR([Could not find phosphor-dbus-interfaces...openbmc/phosphor-dbus-interfaces package required])])
PKG_CHECK_MODULES([SDBUSPLUS], [sdbusplus],,\
    AC_MSG_ERROR(["Requires sdbusplus package."]))


AS_IF([test "x$enable_softoff" != "xno"],
    # Check for sdbusplus
    PKG_CHECK_MODULES([SDBUSPLUS], [sdbusplus],, [AC_MSG_ERROR(["sdbusplus packaged required and not found"])])

    # Check for sdbus++ tool
    [AC_PATH_PROG([SDBUSPLUSPLUS], [sdbus++])]
    AS_IF([test "x$SDBUSPLUSPLUS" == "x"],
          AC_MSG_ERROR([Cannot find sdbus++]))
)

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CFLAGS])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

# Checks for library functions.
LT_INIT([dlopen disable-static shared])
LT_LIB_DLLOAD

# Check/set gtest specific functions.
AX_PTHREAD([GTEST_CPPFLAGS="-DGTEST_HAS_PTHREAD=1"],[GTEST_CPPFLAGS="-DGTEST_HAS_PTHREAD=0"])
AC_SUBST(GTEST_CPPFLAGS)

AC_ARG_ENABLE([oe-sdk],
    AS_HELP_STRING([--enable-oe-sdk], [Link testcases absolutely against OE SDK so they can be ran within it.])
)
AC_ARG_VAR(OECORE_TARGET_SYSROOT,
    [Path to the OE SDK SYSROOT])
AS_IF([test "x$enable_oe_sdk" == "xyes"],
    AS_IF([test "x$OECORE_TARGET_SYSROOT" == "x"],
          AC_MSG_ERROR([OECORE_TARGET_SYSROOT must be set with --enable-oe-sdk])
    )
    AC_MSG_NOTICE([Enabling OE-SDK at $OECORE_TARGET_SYSROOT])
    [
        testcase_flags="-Wl,-rpath,\${OECORE_TARGET_SYSROOT}/lib"
        testcase_flags="${testcase_flags} -Wl,-rpath,\${OECORE_TARGET_SYSROOT}/usr/lib"
        testcase_flags="${testcase_flags} -Wl,-dynamic-linker,`find \${OECORE_TARGET_SYSROOT}/lib/ld-*.so | sort -r -n | head -n1`"
    ]
    AC_SUBST([OESDK_TESTCASE_FLAGS], [$testcase_flags])
)

AC_ARG_VAR(WHITELIST_CONF, [Paths to IPMI whitelisted commands conf files. (default = ${srcdir}/host-ipmid-whitelist.conf)])
if test -z "$WHITELIST_CONF"; then
        WHITELIST_CONF=${srcdir}/host-ipmid-whitelist.conf
fi

AS_IF([test "x$SENSOR_YAML_GEN" == "x"], [SENSOR_YAML_GEN="sensor-example.yaml"])
SENSORGEN="$PYTHON ${srcdir}/scripts/sensor_gen.py -i $SENSOR_YAML_GEN"
AC_SUBST(SENSORGEN)

AS_IF([test "x$INVSENSOR_YAML_GEN" == "x"], [INVSENSOR_YAML_GEN="inventory-sensor-example.yaml"])
INVSENSORGEN="$PYTHON ${srcdir}/scripts/inventory-sensor.py -i $INVSENSOR_YAML_GEN"
AC_SUBST(INVSENSORGEN)

AS_IF([test "x$FRU_YAML_GEN" == "x"], [FRU_YAML_GEN="fru-read-example.yaml"])
FRUGEN="$PYTHON $srcdir/scripts/fru_gen.py -i $FRU_YAML_GEN"
AC_SUBST(FRUGEN)

AC_DEFINE(CALLOUT_FWD_ASSOCIATION, "callout", [The name of the callout's forward association.])
AC_DEFINE(BOARD_SENSOR, "/xyz/openbmc_project/inventory/system/chassis/motherboard", [The inventory path to the motherboard fault sensor.])
AC_DEFINE(SYSTEM_SENSOR, "/xyz/openbmc_project/inventory/system", [The inventory path to the system event sensor.])

# Soft Power off related.
AS_IF([test "x$enable_softoff" != "xno"],
    # Dbus service name
    [AC_ARG_VAR(SOFTOFF_BUSNAME, [The Dbus busname to own])]
    AS_IF([test "x$SOFTOFF_BUSNAME" == "x"],
          [SOFTOFF_BUSNAME="xyz.openbmc_project.Ipmi.Internal.SoftPowerOff"])
    [AC_DEFINE_UNQUOTED([SOFTOFF_BUSNAME], ["$SOFTOFF_BUSNAME"], [The Dbus busname to own])]

    # Service dbus root
    [AC_ARG_VAR(SOFTOFF_OBJPATH, [The SoftPowerOff Dbus root])]
    AS_IF([test "x$SOFTOFF_OBJPATH" == "x"],
          [SOFTOFF_OBJPATH="/xyz/openbmc_project/ipmi/internal/soft_power_off"])
    [AC_DEFINE_UNQUOTED([SOFTOFF_OBJPATH], ["$SOFTOFF_OBJPATH"], [The SoftPowerOff Dbus root])]

    # Timeouts in SECONDS for SoftPowerOff protocol
    [AC_ARG_VAR(IPMI_SMS_ATN_ACK_TIMEOUT_SECS, [Initial timeout for host to ack SMS_ATN from BMC])]
    [AC_DEFINE_UNQUOTED([IPMI_SMS_ATN_ACK_TIMEOUT_SECS], [3], [Initial timeout for host to ack SMS_ATN from BMC])]

    [AC_ARG_VAR(IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS, [Wait time until Host can quiesce])]
    [AC_DEFINE_UNQUOTED([IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS], [5*60], [Wait time until Host can quiesce])]

    # Indicates an in-band power off or reboot request from the host
    # This file is used to ensure the soft off service does not run for host
    # initiated shutdown or reboot requests
    [AC_ARG_VAR(HOST_INBAND_REQUEST_DIR, [Directory used to indicate the host has initiated a shutdown or reboot])]
    AS_IF([test "x$HOST_INBAND_REQUEST_DIR" == "x"],
        [HOST_INBAND_REQUEST_DIR="/run/openbmc/"])
    [AC_DEFINE_UNQUOTED([HOST_INBAND_REQUEST_DIR], ["$HOST_INBAND_REQUEST_DIR"], [Directory to store host initiated shutdown file])]

    [AC_ARG_VAR(HOST_INBAND_REQUEST_FILE, [File which indicates the host has initiated a shutdown or reboot])]
    AS_IF([test "x$HOST_INBAND_REQUEST_FILE" == "x"],
        [HOST_INBAND_REQUEST_FILE="host@%u-request"])
    [AC_DEFINE_UNQUOTED([HOST_INBAND_REQUEST_FILE], ["$HOST_INBAND_REQUEST_FILE"], [File to create if host has initiated shutdown or reboot])]
)

# Control Host Interfaces
# Dbus service name
AC_ARG_VAR(CONTROL_HOST_BUSNAME, [The Control Host Dbus busname to own])
AS_IF([test "x$CONTROL_HOST_BUSNAME" == "x"],
      [CONTROL_HOST_BUSNAME="xyz.openbmc_project.Control.Host"])
AC_DEFINE_UNQUOTED([CONTROL_HOST_BUSNAME], ["$CONTROL_HOST_BUSNAME"], [The Control Host Dbus busname to own])

# Service dbus root
AC_ARG_VAR(CONTROL_HOST_OBJPATH, [The Control Host Dbus root])
AS_IF([test "x$CONTROL_HOST_OBJPATH" == "x"],
      [CONTROL_HOST_OBJPATH="/xyz/openbmc_project/control/host"])
AC_DEFINE_UNQUOTED([CONTROL_HOST_OBJPATH], ["$CONTROL_HOST_OBJPATH"], [The Control Host Dbus root])

# Create configured output
AC_CONFIG_FILES([Makefile test/Makefile softoff/Makefile softoff/test/Makefile])
AC_OUTPUT
