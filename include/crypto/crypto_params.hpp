#pragma once
#include <string>
#include "bigint.hpp"

class CryptoParams {
   public:
    static BigInt rsaN;
    static BigInt rsaD;
    static BigInt rsaE;
    static BigInt pailierN;
    static BigInt pailierLambda;
    static std::string jwtSecret;
    static std::string jwtIssuer;
    static int jwtAuthTokenValidityMinutes;
    static int jwtRefreshTokenValidityMinutes;

    static void loadFromJson(const std::string& configPath);
};