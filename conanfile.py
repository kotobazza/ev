from conan import ConanFile
from conan.tools.env import VirtualRunEnv, Environment
import os

class DrogonAppCustom(ConanFile):
    name = "myapp"
    version = "1.0"
    settings = "os", "compiler", "build_type", "arch"
    generators = "PkgConfigDeps", "MesonToolchain"

    default_options = {
        "drogon/*:with_ctl": True,
        "drogon/*:with_redis": True,
        "drogon/*:with_postgres": True,
    }

    def requirements(self):
        self.requires("drogon/1.9.10")
        self.requires("gtest/1.16.0")
        self.requires("jwt-cpp/0.7.1")
        self.requires("libsodium/1.0.20")
        self.requires("nlohmann_json/3.12.0")

    def generate(self):
        env = VirtualRunEnv(self)
        env.generate()

        drogon_pkg = self.dependencies["drogon"]
        drogon_bin_path = os.path.join(self.build_folder, "deploy", "direct_deploy", "drogon", "bin")
        
        if os.path.exists(drogon_bin_path):
            custom_env = Environment()
            custom_env.prepend_path("PATH", drogon_bin_path)
            custom_env.vars(self).save_script("activate_drogon_ctl")
