
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
conan install . --output-folder=builddir/build_conan -s build_type=Release -d direct_deploy --deployer-folder builddir/build_conan/deploy --build=missing

source builddir/build_conan/activate_drogon_ctl.sh  
export PKG_CONFIG_PATH="$PWD/builddir/build_conan"

meson setup builddir
cd builddir
meson compile    
```
