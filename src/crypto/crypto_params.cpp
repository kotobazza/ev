// src/crypto_params.cpp
#include "crypto_params.hpp"
#include <json/json.h>
#include <fstream>

BigInt CryptoParams::rsaN;
BigInt CryptoParams::rsaD;
BigInt CryptoParams::rsaE;
BigInt CryptoParams::pailierN;
BigInt CryptoParams::pailierLambda;
std::string CryptoParams::jwtSecret;
std::string CryptoParams::jwtIssuer;
int CryptoParams::jwtAuthTokenValidityMinutes;
int CryptoParams::jwtRefreshTokenValidityMinutes;
std::string CryptoParams::votingId;

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

    rsaN = BigInt::fromString(root["123"]["rsa"]["n"].asString());
    rsaD = BigInt::fromString(root["123"]["rsa"]["d"].asString());
    rsaE = BigInt::fromString(root["123"]["rsa"]["e"].asString());
    pailierN = BigInt::fromString(root["123"]["pailier"]["n"].asString());
    pailierLambda = BigInt::fromString(root["123"]["pailier"]["lambda"].asString());
    jwtSecret = root["123"]["jwt"]["jwtSecret"].asString();
    jwtIssuer = root["123"]["jwt"]["jwtIssuer"].asString();
    jwtAuthTokenValidityMinutes = root["123"]["jwt"]["jwtAuthTokenValidityMinutes"].asInt();
    jwtRefreshTokenValidityMinutes = root["123"]["jwt"]["jwtRefreshTokenValidityMinutes"].asInt();
    votingId = root["123"]["voting_id"].asString();
}