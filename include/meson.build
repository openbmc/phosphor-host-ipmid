install_headers(
  'ipmid/api.h',
  'ipmid/api.hpp',
  'ipmid/api-types.hpp',
  'ipmid/filter.hpp',
  'ipmid/handler.hpp',
  'ipmid/iana.hpp',
  'ipmid/message.hpp',
  'ipmid/oemopenbmc.hpp',
  'ipmid/oemrouter.hpp',
  'ipmid/sessiondef.hpp',
  'ipmid/sessionhelper.hpp',
  'ipmid/types.hpp',
  'ipmid/utility.hpp',
  'ipmid/utils.hpp',
  subdir: 'ipmid')

install_headers(
  'ipmid/message/pack.hpp',
  'ipmid/message/types.hpp',
  'ipmid/message/unpack.hpp',
  subdir: 'ipmid/message')

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
