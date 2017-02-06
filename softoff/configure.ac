# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-host-ipmid], [1.0], [https://github.com/openbmc/phosphor-host-ipmid/issues])
AC_LANG([C++])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Check for sdbusplus
AC_PATH_PROG([SDBUSPLUSPLUS], [sdbus++])
AS_IF([test "x$SDBUSPLUSPLUS" == "x"],
    AC_MSG_ERROR([Cannot find sdbus++]))

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

# Checks for libraries.
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221])

LT_INIT # Removes WARNING: unrecognized options: --with-libtool-sysroot

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

# Checks for header files.
AC_CHECK_HEADER(systemd/sd-bus.h, ,[AC_MSG_ERROR([Could not find systemd/sd-bus.h...systemd developement package required])])
AC_CHECK_HEADER(sdbusplus/server.hpp, ,[AC_MSG_ERROR([Could not find sdbusplus/server.hpp...openbmc/sdbusplus package required])])

# Dbus service name
AC_ARG_VAR(BUSNAME, [The Dbus busname to own])
AS_IF([test "x$BUSNAME" == "x"], [BUSNAME="xyz.openbmc_project.Ipmi.SoftPowerOff"])
AC_DEFINE_UNQUOTED([BUSNAME], ["$BUSNAME"], [The Dbus busname to own])

# Service dbus root
AC_ARG_VAR(OBJPATH, [The SoftPowerOff Dbus root])
AS_IF([test "x$OBJPATH" == "x"], [OBJPATH="/xyz/openbmc_project/Ipmi/SoftPowerOff"])
AC_DEFINE_UNQUOTED([OBJPATH], ["$OBJPATH"], [The SoftPowerOff Dbus root])

# Timeouts in SECONDS for SoftPowerOff protocol
AC_ARG_VAR(IPMI_SMS_ATN_ACK_TIMEOUT, [Initial timeout for host to ack SMS_ATN from BMC])
AC_DEFINE_UNQUOTED([IPMI_SMS_ATN_ACK_TIMEOUT], [45], [Initial timeout for host to ack SMS_ATN from BMC])

AC_ARG_VAR(IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT, [Wait time until Host can quiesce])
AC_DEFINE_UNQUOTED([IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT], [45*60], [Wait time until Host can quiesce])

# Create configured output
AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT
