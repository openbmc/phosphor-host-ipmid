project(
    'phosphor-net-ipmid', 'cpp',
    version : '1.0.0',
    meson_version: '>=0.58.0',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++20',
        'buildtype=debugoptimized',
    ]
)

conf_data = configuration_data()
conf_data.set('RMCP_PING', get_option('rmcp_ping').enabled())
conf_data.set('PAM_AUTHENTICATE', get_option('pam_authenticate').enabled())

configure_file(output: 'config.h',
    configuration: conf_data
)

sdbusplus_dep = dependency('sdbusplus')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
libsystemd_dep = dependency('libsystemd')
libcrypto_dep = dependency('libcrypto')
ipmid_dep = dependency('libipmid')
userlayer_dep = dependency('libuserlayer')
channellayer_dep = dependency('libchannellayer')
mapper = dependency('libmapper')

# Project Arguments
cpp = meson.get_compiler('cpp')
add_project_arguments(
  cpp.get_supported_arguments([
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_ALL_NO_LIB',
  ]),
  language : 'cpp')

deps = [
    ipmid_dep,
    userlayer_dep,
    channellayer_dep,
    libcrypto_dep,
    libsystemd_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    mapper,
]

sources = [
    'auth_algo.cpp',
    'sessions_manager.cpp',
    'message_parsers.cpp',
    'message_handler.cpp',
    'command_table.cpp',
    'command/channel_auth.cpp',
    'command/guid.cpp',
    'command/open_session.cpp',
    'command/rakp12.cpp',
    'command/rakp34.cpp',
    'command/session_cmds.cpp',
    'comm_module.cpp',
    'main.cpp',
    'integrity_algo.cpp',
    'crypt_algo.cpp',
    'sd_event_loop.cpp',
    'sol/sol_manager.cpp',
    'sol/sol_context.cpp',
    'command/sol_cmds.cpp',
    'command/payload_cmds.cpp',
    'sol_module.cpp',
]

executable(
    'netipmid',
    sources,
    implicit_include_directories: true,
    include_directories: ['command', 'sol'],
    dependencies: deps,
    install: true,
    install_dir: get_option('bindir')
)

systemd = dependency('systemd')
systemd_system_unit_dir = systemd.get_variable(
        'systemdsystemunitdir',
        pkgconfig_define: ['prefix', get_option('prefix')])

configure_file(input: 'phosphor-ipmi-net@.service',
                output: 'phosphor-ipmi-net@.service',
                copy: true,
                install_dir: systemd_system_unit_dir)

configure_file(input: 'phosphor-ipmi-net@.socket',
                output: 'phosphor-ipmi-net@.socket',
                copy: true,
                install_dir: systemd_system_unit_dir)

build_tests = get_option('tests')
if not build_tests.disabled()
  subdir('test')
endif
