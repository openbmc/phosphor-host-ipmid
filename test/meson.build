gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
gmock_dep = dependency('gmock', disabler: true, required: false)
if not gtest_dep.found() or not gmock_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ]
        )
        gmock_dep = gtest_proj.dependency('gmock')
  else
        assert(
            not get_option('tests').enabled(),
            'Googletest is required if tests are enabled'
        )
  endif
endif

test_sources = [
  '../integrity_algo.cpp',
  '../crypt_algo.cpp',
]

tests = [
  'cipher.cpp',
]

foreach t : tests
  test(t, executable(t.underscorify(), t,
                     test_sources,
                     include_directories: ['..'],
                     dependencies: [
                         gtest_dep,
                         gmock_dep,
                         libcrypto_dep,
                         ]),
       workdir: meson.current_source_dir())
endforeach