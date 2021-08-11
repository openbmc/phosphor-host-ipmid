project(
  'phosphor-host-ipimd',
  'cpp',
  version: '0.1',
  meson_version: '>=0.57.0',
  default_options: [
    'werror=false',
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


if get_option('update-functional-on-fail') != ''
  conf_data.set_quoted('HOST_IPMI_LIB_PATH', get_option('update-functional-on-fail'))
endif

conf_h = configure_file(
  output: 'config.h',
  configuration: conf_data,
)

root = meson.current_source_dir()
root_inc = include_directories('.', 'include')

cpp = meson.get_compiler('cpp')

if cpp.has_header('nlohmann/json.hpp')
    nlohmann_json = declare_dependency()
else
    subproject('nlohmann_json', required: false)
    nlohmann_json = declare_dependency(
        include_directories: [
            '../subprojects/nlohmann_json',
        ]
    )
    nlohmann_json = nlohmann_json.as_system('system')
endif

boost_compile_args = [
  '-DBOOST_ASIO_DISABLE_THREADS',
  '-DBOOST_ALL_NO_LIB',
  '-DBOOST_SYSTEM_NO_DEPRECATED',
  '-DBOOST_ERROR_CODE_HEADER_ONLY',
  '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
]

boost_dep = dependency('boost', version : '>=1.74.0', required : false)

if not boost_dep.found()
 subproject('boost', required: false)
 boost_inc = include_directories('../subprojects/boost_1_75_0/', is_system:true)
 boost = declare_dependency(include_directories : boost_inc)
 boost = boost.as_system('system')
endif

# boost_inc = include_directories('../subprojects/boost_1_75_0/', is_system:true)
# boost  = declare_dependency(include_directories : boost_inc)
# boost = boost.as_system('system')

phosphor_logging_dep = dependency(
  'phosphor-logging',
  fallback: ['phosphor-logging', 'phosphor_logging_dep']
)

phosphor_dbus_interfaces_dep = dependency(
  'phosphor-dbus-interfaces',
  fallback: ['phosphor-dbus-interfaces', 'phosphor_dbus_interfaces_dep']
)

sdbusplus_dep = dependency('sdbusplus', required: false)
if sdbusplus_dep.found() and sdbusplus_dep.type_name() != 'internal'
    sdbusplusplus_prog = find_program('sdbus++', native: true)
    sdbuspp_gen_meson_prog = find_program('sdbus++-gen-meson', native: true)
else
    sdbusplus_proj = subproject('sdbusplus', required: true)
    sdbusplus_dep = sdbusplus_proj.get_variable('sdbusplus_dep')
    sdbusplusplus_prog = sdbusplus_proj.get_variable('sdbusplusplus_prog')
    sdbuspp_gen_meson_prog = sdbusplus_proj.get_variable(
        'sdbuspp_gen_meson_prog'
    )
endif

systemd = dependency('systemd')
crypto = dependency('libcrypto', version : '>=1.0.2g')
pam = cpp.find_library('pam', required: true)
# mapper = cpp.find_library('mapper', required: true)

feature_map = {
  'boot-flag-safe-mode-support': '-DENABLE_BOOT_FLAG_SAFE_MODE_SUPPORT',
  'i2c-whitelist-check':       '-DENABLE_I2C_WHITELIST_CHECK',
  'update-functional-on-fail': '-DUPDATE_FUNCTIONAL_ON_FAIL',
  'dynamic-sensors':           '-DFEATURE_DYNAMIC_SENSORS',
  'dynamic-sensors-write':     '-DFEATURE_DYNAMIC_SENSORS_WRITE',
  'hybrid-sensors':            '-DFEATURE_HYBRID_SENSORS'
}

add_project_arguments(
  cpp.get_supported_arguments([
    '-flto',
	  '-Wno-psabi',
	  boost_compile_args
  ]),
  language: 'cpp',
)

subdir('scripts')

# ipmid
'''
ipmid_pre = [
  sdeventplus_dep,
  sdbusplus_dep,
  phosphor_logging_dep,
  phosphor_dbus_interfaces_dep,
  boost_dep,
  mapper,
  ipmid_dep,
  channellayer_dep,
  ipmidhost_dep
]

libipmi20_src = [
  'sensor-gen.cpp',
  'inventory-sensor-gen.cpp',
  'fru-read-gen.cpp',
]

ipmid_lib = static_library(
  'ipmid_lib',
  'host-cmd-manager.cpp',
  libipmi20_src,
  conf_h,
  dependencies: ipmid_pre,
  include_directories: root_inc,
)

ipmid_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: softpower_lib,
)

executable(
  'ipmid',
  'ipmid-new.cpp',
  implicit_include_directories: false,
  dependencies: softpower_dep,
  include_directories: root_inc,
  install: true,
  install_dir: get_option('bindir'),
)
'''


# Subfolders
subdir('dbus-sdr')
subdir('libipmid')

if not get_option('softoff').disabled()
  subdir('xyz/openbmc_project/Ipmi/Internal/SoftPowerOff')
  # subdir('softoff')
endif

if not get_option('libuserlayer').disabled()
  # subdir('user_channel')
endif

if not get_option('tests').disabled()
  # subdir('test')
endif


# Generate Configuration Files from Yaml
python_exe = find_program('python3', 'python')

sensor_yaml_script = files('scripts/sensor_gen.py')
sensor_yaml_gen = run_command( \
  python_exe, \
  sensor_yaml_script, \
  '-i', 'scripts/' + get_option('sensor-yaml-gen'), \
  '-o', meson.project_build_root(), \
  'generate-cpp',
)
if sensor_yaml_gen.returncode() != 0
  error(sensor_yaml_gen.stderr())
endif

invsensor_yaml_script = files('scripts/inventory-sensor.py')
invsensor_yaml_gen = run_command( \
  python_exe, \
  invsensor_yaml_script, \
  '-i', 'scripts/' + get_option('invsensor-yaml-gen'), \
  '-o', meson.project_build_root(), \
  'generate-cpp',
)
if invsensor_yaml_gen.returncode() != 0
  error(invsensor_yaml_gen.stderr())
endif

fru_yaml_script = files('scripts/fru_gen.py')
fru_yaml_gen = run_command( \
  python_exe, \
  fru_yaml_script, \
  '-i', 'scripts/' + get_option('fru-yaml-gen'), \
  '-o', meson.project_build_root(), \
  'generate-cpp',
)
if fru_yaml_gen.returncode() != 0
  error(fru_yaml_gen.stderr())
endif

subdir('include')
