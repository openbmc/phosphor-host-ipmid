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

AS_IF([test "x$enable_softoff" != "xno"],
    # Check for sdbusplus
    AX_PKG_CHECK_MODULES([SDBUSPLUS], [], [sdbusplus], [], [AC_MSG_ERROR(["sdbusplus packaged required and not found"])])

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

# Soft Power off related.
AS_IF([test "x$enable_softoff" != "xno"],
    # Dbus service name
    [AC_ARG_VAR(BUSNAME, [The Dbus busname to own])]
    AS_IF([test "x$BUSNAME" == "x"],
          [BUSNAME="xyz.openbmc_project.Ipmi.SoftPowerOff"])
    [AC_DEFINE_UNQUOTED([BUSNAME], ["$BUSNAME"], [The Dbus busname to own])]

    # Service dbus root
    [AC_ARG_VAR(OBJPATH, [The SoftPowerOff Dbus root])]
    AS_IF([test "x$OBJPATH" == "x"],
          [OBJPATH="/xyz/openbmc_project/ipmi/softpoweroff"])
    [AC_DEFINE_UNQUOTED([OBJPATH], ["$OBJPATH"], [The SoftPowerOff Dbus root])]

    # Timeouts in SECONDS for SoftPowerOff protocol
    [AC_ARG_VAR(IPMI_SMS_ATN_ACK_TIMEOUT_SECS, [Initial timeout for host to ack SMS_ATN from BMC])]
    [AC_DEFINE_UNQUOTED([IPMI_SMS_ATN_ACK_TIMEOUT_SECS], [3], [Initial timeout for host to ack SMS_ATN from BMC])]

    [AC_ARG_VAR(IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS, [Wait time until Host can quiesce])]
    [AC_DEFINE_UNQUOTED([IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS], [45*60], [Wait time until Host can quiesce])]
)

# Create configured output
AC_CONFIG_FILES([Makefile test/Makefile softoff/Makefile softoff/test/Makefile])
AC_OUTPUT
