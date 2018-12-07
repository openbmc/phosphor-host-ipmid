sdeventplus = dependency('sdeventplus')

executable(
  'phosphor-softoff',
  [
    'mainapp.cpp',
    'softoff.cpp',
    softoff_server_hxx,
    softoff_server_cxx,
  ],
  include_directories: includes,
  implicit_include_directories: false,
  link_with: utils,
  dependencies: [
    phosphor_dbus_interfaces,
    phosphor_logging,
    sdbusplus,
    sdeventplus,
  ],
  export_dynamic: true,
  install: true)
