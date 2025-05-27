# example OEM library build

example_oem_src = ['apphandler.cpp']

example_oem_deps = [
    boost,
    crypto,
    ipmid_dep,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    stdplus_dep,
]


example_oem_lib = library(
    'example-oem',
    example_oem_src,
    dependencies: example_oem_deps,
    include_directories: [root_inc],
    install: true,
    install_dir: get_option('libdir') / 'ipmid-providers',
    version: meson.project_version(),
    override_options: ['b_lundef=false'],
)
