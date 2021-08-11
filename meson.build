project(
  'phosphor-host-ipimd',
  'cpp',
  version: '0.1',
  meson_version: '>=0.57.0',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++20',
  ],
)

# Setting up config data
conf_data = configuration_data()

# The name of the callout's forward association
conf_data.set_quoted('CALLOUT_FWD_ASSOCIATION', 'callout')
conf_data.set_quoted('BOARD_SENSOR', get_option('board-sensor'))
conf_data.set_quoted('SYSTEM_SENSOR', get_option('system-sensor'))

# Soft Power off related.
if not get_option('softoff').disabled()
  conf_data.set_quoted('SOFTOFF_BUSNAME', get_option('softoff-busname'))
  conf_data.set_quoted('SOFTOFF_OBJPATH', get_option('softoff-objpath'))
  conf_data.set('IPMI_SMS_ATN_ACK_TIMEOUT_SECS', get_option('ipmi-sms-atn-ack-timeout-secs'))
  conf_data.set('IPMI_HOST_SHUTDOWN_COMPLETE_TIMEOUT_SECS', get_option('ipmi-host-shutdown-complete-timeout-secs'))
  conf_data.set_quoted('HOST_INBAND_REQUEST_DIR', get_option('host-inband-request-dir'))
  conf_data.set_quoted('HOST_INBAND_REQUEST_FILE', get_option('host-inband-request-file'))
endif

conf_data.set_quoted('CONTROL_HOST_BUSNAME', get_option('control-host-busname'))
conf_data.set_quoted('CONTROL_HOST_OBJ_MGR', get_option('control-host-obj-mgr'))
conf_data.set_quoted('HOST_NAME', get_option('host-name'))
conf_data.set_quoted('POWER_READING_SENSOR', get_option('power-reading-sensor'))
conf_data.set_quoted('HOST_IPMI_LIB_PATH', get_option('host-ipmi-lib-path'))

conf_h = configure_file(
  output: 'config.h',
  configuration: conf_data,
)

root = meson.current_source_dir()
root_inc = include_directories('.', 'include')

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

boost_compile_args = []

phosphor_logging_dep = dependency(
  'phosphor-logging',
  fallback: ['phosphor-logging', 'phosphor_logging_dep']
)

phosphor_dbus_interfaces_dep = dependency(
  'phosphor-dbus-interfaces',
  fallback: ['phosphor-dbus-interfaces', 'phosphor_dbus_interfaces_dep']
)

sdbusplus_dep = dependency('sdbusplus', required : false, include_type: 'system')
if not sdbusplus_dep.found()
  sdbusplus_proj = subproject('sdbusplus', required: true)
  sdbusplus_dep = sdbusplus_proj.get_variable('sdbusplus_dep')
  sdbusplus_dep = sdbusplus_dep.as_system('system')
endif

sdeventplus_dep = dependency('sdeventplus', fallback: ['sdeventplus', 'sdeventplus_dep'])

systemd = dependency('systemd')
crypto = dependency('libcrypto', version : '>=1.0.2g')
pam = cpp.find_library('pam', required: true)
mapper = cpp.find_library('mapper', required: true)

feature_map = {
  'boot-flag-safe-mode-support': '-DENABLE_BOOT_FLAG_SAFE_MODE_SUPPORT',
  'i2c-whitelist-check'        : '-DENABLE_I2C_WHITELIST_CHECK',
  'update-functional-on-fail'  : '-DUPDATE_FUNCTIONAL_ON_FAIL',
  'dynamic-sensors'            : '-DFEATURE_DYNAMIC_SENSORS',
  'dynamic-sensors-write'      : '-DFEATURE_DYNAMIC_SENSORS_WRITE',
  'hybrid-sensors'             : '-DFEATURE_HYBRID_SENSORS',
  'sensors-cache'              : '-DFEATURE_SENSORS_CACHE',
  'sel-logger-clears-sel'      : '-DFEATURE_SEL_LOGGER_CLEARS_SEL',
}

foreach option_key, option_value : feature_map
  if(get_option(option_key).enabled())
    summary(option_key,option_value, section : 'Enabled Features')
    add_project_arguments(option_value,language:'cpp')
  endif
endforeach

add_project_arguments(
  cpp.get_supported_arguments([
    '-flto',
    '-Wno-psabi',
    '-Wno-missing-field-initializers',
    '-Wno-pedantic',
    boost_compile_args
  ]),
  language: 'cpp',
)

boost_coroutine = cpp.find_library('boost_coroutine', required: true)
std_cpp_fs = cpp.find_library('stdc++fs', required: true)

# Main Files
ipmid_main_lib = static_library(
  'ipmid_main',
  'ipmid-new.cpp',
  'host-cmd-manager.cpp',
  'settings.cpp',
  include_directories: root_inc,
)

ipmid_main_dep = declare_dependency(
  include_directories: root_inc,
  link_with: ipmid_main_lib,
)

# Subfolders
subdir('libipmid')
subdir('include')
subdir('user_channel')
subdir('app')
subdir('scripts')


if not get_option('softoff').disabled()
  subdir('xyz/openbmc_project/Ipmi/Internal/SoftPowerOff')
  subdir('softoff')
endif

# whitelist
generate_whitelist_script = files('generate_whitelist_create.sh')

whitelist_conf = get_option('whitelist-conf')

ipmiwhitelist = run_command( \
  'bash', \
  generate_whitelist_script, \
  whitelist_conf, \
)

whitelist_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    channellayer_dep,
    crypto,
    ipmid_dep,
    ipmid_main_dep,
    phosphor_dbus_interfaces_dep,
    sdbusplus_dep,
  ],
)

whitelist_lib = library(
  'whitelist',
  'whitelist-filter.cpp',
  'ipmiwhitelist.cpp',
  implicit_include_directories: false,
  dependencies: whitelist_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

whitelist_dep = declare_dependency(
  link_with: whitelist_lib,
  dependencies: whitelist_pre,
)

# libsysintfcmds
sysintfcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    ipmid_main_dep,
    channellayer_dep,
    crypto,
    mapper,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
  ],
)

sysintfcmds_lib = library(
  'sysintfcmds',
  'systemintfcmds.cpp',
  'host-interface.cpp',
  implicit_include_directories: false,
  dependencies: sysintfcmds_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

sysintfcmds_dep = declare_dependency(
  link_with: sysintfcmds_lib,
  dependencies: sysintfcmds_pre,
)

# ipmid
ipmid_pre = [
  sdeventplus_dep,
  sdbusplus_dep,
  phosphor_logging_dep,
  phosphor_dbus_interfaces_dep,
  ipmid_dep,
  channellayer_dep,
  userlayer_dep,
  boost_coroutine,
  crypto,
  app_dep,
  std_cpp_fs,
  pam,
  mapper,
]

generated_src = [
  meson.project_build_root() + '/sensor-gen.cpp',
  meson.project_build_root() + '/inventory-sensor-gen.cpp',
  meson.project_build_root() + '/fru-read-gen.cpp',
]

ipmi_whitelist_src = []
if not get_option('ipmi-whitelist').disabled()
  ipmi_whitelist_src = ['ipmiwhitelist.cpp']
endif

transportoem_src = []
if not get_option('transport-oem').disabled()
  transportoem_src = ['transporthandler_oem.cpp']
endif

libipmi20_src = [
  'apphandler.cpp',
  'sys_info_param.cpp',
  'sensorhandler.cpp',
  'entity_map_json.cpp',
  'storagehandler.cpp',
  'chassishandler.cpp',
  'dcmihandler.cpp',
  'ipmisensor.cpp',
  'storageaddsel.cpp',
  'transporthandler.cpp',
  'globalhandler.cpp',
  'groupext.cpp',
  'selutility.cpp',
  'ipmi_fru_info_area.cpp',
  'read_fru_data.cpp',
  'sensordatahandler.cpp',
  generated_src,
  ipmi_whitelist_src,
  transportoem_src,
  conf_h,
]

ipmi20_lib = library(
  'libipmi20',
  libipmi20_src,
  dependencies: ipmid_pre,
  include_directories: root_inc,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

libipmi20_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: ipmi20_lib,
)

executable(
  'ipmid',
  'ipmid-new.cpp',
  'host-cmd-manager.cpp',
  'settings.cpp',
  implicit_include_directories: false,
  dependencies: [ipmid_main_dep, libipmi20_dep],
  include_directories: root_inc,
  install: true,
  install_dir: get_option('bindir'),
)

# Dynamic Sensor Stack
subdir('dbus-sdr')

if not get_option('tests').disabled()
  subdir('test')
endif

install_subdir(
  'user_channel',
  install_dir: get_option('includedir'),
  strip_directory: false,
  exclude_files: '*.cpp',
)
