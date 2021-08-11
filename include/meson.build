install_subdir(
  'dbus-sdr',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp',
)

install_subdir(
  'ipmid',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp',
)

install_subdir(
  'ipmid-host',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp',
)

# Eventually we will split <ipmid/*> and <host-ipmid/*> headers
# For now they will be the same during migration
install_data(
  'ipmid/iana.hpp',
  'ipmid/api.h',
  'ipmid/oemopenbmc.hpp',
  'ipmid/oemrouter.hpp',
  'ipmid-host/cmd.hpp',
  'ipmid-host/cmd-utils.hpp',
  install_dir: get_option('includedir') / 'host-ipmid',
  rename: [
    'iana.hpp',
    'ipmid-api.h',
    'oemopenbmc.hpp',
    'oemrouter.hpp',
    'ipmid-host-cmd.hpp',
    'ipmid-host-cmd-utils.hpp',
  ]
)
