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

# Добавляем GTest (будет найден через Conan)
gtest_dep = dependency('gtest')  # Без `main: true`

crypto_includes = include_directories('include/crypto')
controllers_includes = include_directories('include/controllers')

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

# Генерация view из .csp файлов
view_sources = []
view_headers = []

# Получаем список .csp файлов
csp_files = []
views_dir = meson.current_source_dir() / 'views'
if run_command('test', '-d', views_dir, check: false).returncode() == 0
  csp_files = run_command('find', views_dir, '-name', '*.csp', check: false)
  if csp_files.returncode() == 0
    foreach csp_file : csp_files.stdout().split('\n')
      if csp_file != ''
        message('Processing csp file:', csp_file)
        classname = run_command('basename', '-s', '.csp', csp_file, check: true).stdout().strip()
        message('Generating view class:', classname)
        
        # Генерируем файлы через custom_target
        generated = custom_target(
          'view_' + classname,
          output: [classname + '.h', classname + '.cc'],
          input: csp_file,
          command: ['drogon_ctl', 'create', 'view', '@INPUT@'],
          build_by_default: true,
        )
        
        # Добавляем сгенерированные файлы в список источников
        view_sources += generated[1]  # .cc файл
        view_headers += generated[0]  # .h файл
      endif
    endforeach
  else
    warning('Не удалось найти .csp файлы в директории views')
  endif
else
  warning('Директория views не найдена')
endif

executable_sources = files([
  'src/main.cpp',
  'src/controllers/test_controller.cpp'
])

executable('drogon_demo',
  sources: executable_sources + view_sources,
  dependencies: deps,
  include_directories: [controllers_includes, crypto_includes],
  install: true)

test_sources = files([
  'tests/tests.cpp',
])

if test_sources.length() > 0
  test_exec = executable('drogon_tests',
    sources: test_sources + view_sources,
    dependencies: deps + [gtest_dep],
    include_directories: crypto_includes,
    install: false)

  test('Drogon tests', test_exec)
endif





run_command('mkdir', '-p', meson.current_build_dir() / 'logs', check: false)