# Generate Configuration Files from Yaml
python_exe = find_program('python3', 'python')

sensor_yaml_script = files('sensor_gen.py')
sensor_yaml_gen = run_command( \
  python_exe, \
  sensor_yaml_script, \
  '-i', get_option('sensor-yaml-gen'), \
  '-o', meson.project_build_root(), \
  'generate-cpp')
if sensor_yaml_gen.returncode() != 0
  error(sensor_yaml_gen.stderr())
endif

invsensor_yaml_script = files('inventory-sensor.py')
invsensor_yaml_gen = run_command( \
  python_exe, \
  invsensor_yaml_script, \
  '-i', get_option('invsensor-yaml-gen'), \
  '-o', meson.project_build_root(), \
  'generate-cpp')
if invsensor_yaml_gen.returncode() != 0
  error(invsensor_yaml_gen.stderr())
endif

fru_yaml_script = files('fru_gen.py')
fru_yaml_gen = run_command( \
  python_exe, \
  fru_yaml_script, \
  '-i', get_option('fru-yaml-gen'), \
  '-o', meson.project_build_root(), \
  'generate-cpp')
if fru_yaml_gen.returncode() != 0
  error(fru_yaml_gen.stderr())
endif
