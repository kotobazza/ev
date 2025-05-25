#include <drogon/drogon.h>
#include "crypto_params.hpp"

int main() {
    try {
        CryptoParams::loadFromJson("../crypto_params.json");
    } catch (const std::exception& e) {
        std::cerr << "Failed to load crypto parameters: " << e.what() << std::endl;
        return 1;
    }
    drogon::app().loadConfigFile("../config.json");
    drogon::app().run();
    return 0;
}