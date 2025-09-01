# nvidia OEM library build

nvidia_oem_src = [
    'biosconfigcommands.cpp',
    'bootstrap-credentials-oem-cmds.cpp',
    'sbmr-oem.cpp',
]

nvidia_oem_deps = [
    boost,
    crypto,
    ipmid_dep,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    stdplus_dep,
]

nvidia_ipmi_oem = library(
    'nvidia_ipmi_oem',
    nvidia_oem_src,
    dependencies: nvidia_oem_deps,
    include_directories: [root_inc],
    install: true,
    install_dir: get_option('libdir') / 'ipmid-providers',
    version: meson.project_version(),
    override_options: ipmi_plugin_options,
)
