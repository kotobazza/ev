#pragma once
#include "bigint.hpp"

class CryptoParams {
   public:
    static BigInt rsaN;
    static BigInt rsaD;
    static BigInt rsaE;
    static BigInt pailierN;
    static BigInt pailierLambda;

    static void loadFromJson(const std::string& configPath);
};