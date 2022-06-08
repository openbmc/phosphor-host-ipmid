install_subdir(
  'dbus-sdr',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp')

install_subdir(
  'ipmid',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp')

install_subdir(
  'ipmid-host',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp')

# install the ipmid-host and ipmid includes
install_subdir('ipmid-host', install_dir: get_option('includedir'))
install_subdir('ipmid', install_dir: get_option('includedir'))
