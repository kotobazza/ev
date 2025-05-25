// src/crypto_params.cpp
#include "crypto_params.hpp"
#include <json/json.h>
#include <fstream>

BigInt CryptoParams::rsaN;
BigInt CryptoParams::rsaD;
BigInt CryptoParams::rsaE;
BigInt CryptoParams::pailierN;
BigInt CryptoParams::pailierLambda;

void CryptoParams::loadFromJson(const std::string& configPath) {
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        throw std::runtime_error("Cannot open config file: " + configPath);
    }

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;

    if (!Json::parseFromStream(builder, configFile, &root, &errors)) {
        throw std::runtime_error("Failed to parse config: " + errors);
    }

    rsaN = BigInt::fromString(root["rsa"]["n"].asString());
    rsaD = BigInt::fromString(root["rsa"]["d"].asString());
    rsaE = BigInt::fromString(root["rsa"]["e"].asString());
    pailierN = BigInt::fromString(root["pailier"]["n"].asString());
    pailierLambda = BigInt::fromString(root["pailier"]["lambda"].asString());
}