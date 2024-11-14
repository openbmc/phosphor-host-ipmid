gtest = dependency('gtest', main: true, disabler: true, required: false)
gmock = dependency('gmock', disabler: true, required: false)
if not gtest.found() or not gmock.found()
    gtest_opts = import('cmake').subproject_options()
    gtest_opts.add_cmake_defines({'CMAKE_CXX_FLAGS': '-Wno-pedantic'})
    gtest_proj = import('cmake').subproject(
        'googletest',
        options: gtest_opts,
        required: false
    )
    if gtest_proj.found()
        gtest = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ])
        gmock = gtest_proj.dependency('gmock')
    else
        assert(not get_option('tests').enabled(), 'Googletest is required')
    endif
endif

# Build/add serial_unittest to test suite
test('transport_serial',
    executable(
        'transport_serial_unittest',
        'serial_unittest.cpp',
        '../serialcmd.cpp',
        include_directories: root_inc,
        build_by_default: false,
        implicit_include_directories: false,
        dependencies: [
            sdbusplus_dep,
            stdplus_dep,
            phosphor_logging_dep,
            sdeventplus_dep,
            gtest,
            gmock
        ]
    )
)
