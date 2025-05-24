
deps = [
    libsystemd_dep,
    systemd_dep,
    sdeventplus_dep,
    stdplus_dep,
    sdbusplus_dep,
    phosphor_logging_dep,
    cli11_dep,
]

serialbridged = executable(
    'serialbridged',
    'serialbridged.cpp',
    'serialcmd.cpp',
    dependencies: deps,
    install: true,
    install_dir: get_option('libexecdir'),
)

# Configure and install systemd unit files
serial_conf_data = configuration_data()
serial_conf_data.set(
    'BIN',
    get_option('prefix') / get_option('libexecdir') / serialbridged.name(),
)
configure_file(
    input: 'serialbridge@.service.in',
    output: 'serialbridge@.service',
    configuration: serial_conf_data,
    install: true,
    install_dir: systemd_dep.get_variable(pkgconfig: 'systemdsystemunitdir'),
)

if get_option('tests').allowed()
    subdir('test')
endif
