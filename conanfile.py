from conan import ConanFile
from conan.tools.env import VirtualRunEnv, Environment
import os

class DrogonAppCustom(ConanFile):
    name = "myapp"
    version = "1.0"
    settings = "os", "compiler", "build_type", "arch"
    generators = "PkgConfigDeps", "MesonToolchain"

    def requirements(self):
        self.requires("drogon/1.9.10")
        self.requires("gtest/1.16.0")

    def configure(self):
        self.options["drogon"].with_ctl = True
        self.options["drogon"].with_redis = True
        self.options["drogon"].with_postgres = True

    def generate(self):
        # Стандартное окружение для зависимостей
        env = VirtualRunEnv(self)
        env.generate()

        

        # Добавляем путь к drogon_ctl в runenv_info
        drogon_pkg = self.dependencies["drogon"]
        drogon_bin_path = os.path.join(self.build_folder, "deploy", "direct_deploy", "drogon", "bin")
        
        if os.path.exists(drogon_bin_path):
            # Создаём кастомное окружение
            
            custom_env = Environment()
            custom_env.prepend_path("PATH", drogon_bin_path)
            
            # Сохраняем его в отдельный скрипт
            custom_env.vars(self).save_script("activate_drogon_ctl")