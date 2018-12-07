sdbusplus_tool = find_program('sdbus++', native: true)

softoff_interface = 'xyz.openbmc_project.Ipmi.Internal.SoftPowerOff'
softoff_yaml = files(join_paths(meson.source_root(), softoff_interface.split('.')) +
  '.interface.yaml')

softoff_server_hxx = custom_target(
  'softoff-server-hxx',
  input: softoff_yaml,
  output: ['server.hpp'],
  capture: true,
  command: [
    sdbusplus_tool,
    '-r', meson.source_root(),
    'interface', 'server-header',
    softoff_interface
  ])

softoff_server_cxx = custom_target(
  'softoff-server-cxx',
  input: softoff_yaml,
  output: ['server.cpp'],
  capture: true,
  command: [
    sdbusplus_tool,
    '-r', meson.source_root(),
    'interface', 'server-cpp',
    softoff_interface
  ])

