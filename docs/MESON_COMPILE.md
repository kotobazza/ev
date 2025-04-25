
*За кадром*
+ Профиль conan2
```
[settings]
arch=x86_64
build_type=Release
compiler=gcc
compiler.cppstd=gnu17
compiler.libcxx=libstdc++11
compiler.version=14
os=Linux
```

С этими настройками и какими-то еще установленными пакетами (находится в [Dependencies](DEPENDENCIES.md) эта сборка заработала у меня на Fedora) 



## Процесс установки
```bash
mkdir build
conan install . --output-folder=build --build=missing
export PKG_CONFIG_PATH="$PWD/build"
meson setup builddir --prefix=$PWD/install    
cd builddir
meson compile       
```
