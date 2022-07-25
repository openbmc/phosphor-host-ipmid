# Generate Configuration Files from Yaml
python_exe = find_program('python3', 'python')

sensor_gen = custom_target('sensor-gen',
    output: 'sensor-gen.cpp',
    input: [ 'sensor_gen.py', get_option('sensor-yaml-gen')],
    command: [
        python_exe,
        '@INPUT0@',
        '-i', '@INPUT1@',
        '-o', meson.current_build_dir(),
        'generate-cpp',
    ],
)
generated_src += sensor_gen

invsensor_gen = custom_target('invsensor-gen',
    output: 'inventory-sensor-gen.cpp',
    input: [ 'inventory-sensor.py', get_option('invsensor-yaml-gen')],
    command: [
        python_exe,
        '@INPUT0@',
        '-i', '@INPUT1@',
        '-o', meson.current_build_dir(),
        'generate-cpp',
    ],
)
generated_src += invsensor_gen

fru_gen = custom_target('fru-gen',
    output: 'fru-read-gen.cpp',
    input: [ 'fru_gen.py', get_option('fru-yaml-gen') ],
    command: [
        python_exe,
        '@INPUT0@',
        '-i', '@INPUT1@',
        '-o', meson.current_build_dir(),
        'generate-cpp',
    ],
)
generated_src += fru_gen
