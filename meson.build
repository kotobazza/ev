project('drogon_app', 'cpp',
  default_options: ['cpp_std=c++17'])

# Ищем зависимости через pkg-config (сгенерированные Conan)
deps = [

  dependency('drogon'),
  dependency('jsoncpp'),
  dependency('openssl'),
  dependency('zlib'),
  dependency('threads'),
  dependency('trantor'),
]

drogon_ctl_check = run_command(
  'sh', '-c', 
  '. @0@/build_conan/activate_drogon_ctl.sh && which drogon_ctl'.format(meson.current_build_dir()),
  check: false
)

if drogon_ctl_check.returncode() != 0
  warning('''
    drogon_ctl не найден! Возможно, не активировано окружение Drogon.
    Выполните вручную:
      source @0@/build_conan/activate_drogon_ctl.sh
    или убедитесь, что Drogon установлен через Conan.
  '''.format(meson.current_build_dir()))
else
  message('drogon_ctl найден:', drogon_ctl_check.stdout().strip())
endif

executable('drogon_demo',
  sources: ['src/main.cpp'],
  dependencies: deps,
  install: true)

run_command('mkdir', '-p', meson.current_build_dir() / 'logs', check: false)

