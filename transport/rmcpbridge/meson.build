
rmcp_conf_data = configuration_data()
rmcp_conf_data.set('RMCP_PING', get_option('rmcp_ping').allowed())
rmcp_conf_data.set('PAM_AUTHENTICATE', get_option('pam_authenticate').allowed())

configure_file(output: 'config.h', configuration: rmcp_conf_data)

# Project Arguments
cpp = meson.get_compiler('cpp')

libcrypto_dep = dependency('libcrypto')

deps = [
    cli11_dep,
    ipmid_dep,
    userlayer_dep,
    channellayer_dep,
    libcrypto_dep,
    libsystemd_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
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

rmcpbridge = executable(
    'rmcpbridge',
    sources,
    implicit_include_directories: true,
    include_directories: ['command', 'sol'],
    dependencies: deps,
    install: true,
    install_dir: get_option('bindir'),
)

systemd_system_unit_dir = systemd_dep.get_variable(
    'systemdsystemunitdir',
    pkgconfig_define: ['prefix', get_option('prefix')],
)

rmcp_unit_conf_data = configuration_data()
rmcp_unit_conf_data.set(
    'BIN',
    get_option('prefix') / get_option('libexecdir') / rmcpbridge.name(),
)

configure_file(
    input: 'rmcpbridge@.service.in',
    output: 'rmcpbridge@.service',
    configuration: rmcp_unit_conf_data,
    install: true,
    install_dir: systemd_system_unit_dir,
)

configure_file(
    input: 'rmcpbridge@.socket',
    output: 'rmcpbridge@.socket',
    copy: true,
    install_dir: systemd_system_unit_dir,
)

build_tests = get_option('tests')
if build_tests.allowed()
    subdir('test')
endif
