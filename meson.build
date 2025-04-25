project('drogon_app', 'cpp',
  default_options: ['cpp_std=c++17'])

# Ищем зависимости через pkg-config (сгенерированные Conan)
deps = [
  dependency('drogon'),
  dependency('jsoncpp'),
  dependency('openssl'),
  dependency('zlib'),
  dependency('threads'),
]

executable('drogon_demo',
  sources: 'src/main.cpp',
  dependencies: deps,
  install: true)