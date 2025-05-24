#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include "bigint.hpp"

using namespace std;

BigInt L(const BigInt& x, const BigInt& n) {
    return (x - BigInt(1)) / n;
}

tuple<BigInt, BigInt, BigInt> generate_keys(const BigInt& p, const BigInt& q) {
    BigInt n = p * q;
    BigInt lambda = lcm(p - BigInt(1), q - BigInt(1));
    BigInt g = n + BigInt(1);
    return {n, lambda, g};
}

BigInt encrypt(const BigInt& m, const BigInt& r, const BigInt& g, const BigInt& n) {
    BigInt nn = n * n;
    return (g.modExp(m, nn) * r.modExp(n, nn)) % nn;
}

BigInt decrypt(const BigInt& c, const BigInt& g, const BigInt& lambda, const BigInt& n) {
    BigInt nn = n * n;
    BigInt numerator = L(c.modExp(lambda, nn), n);
    BigInt denominator = L(g.modExp(lambda, nn), n);
    return (numerator * denominator.modInverse(n)) % n;
}

BigInt compute_digest(const vector<BigInt>& values) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        // Обработка ошибки выделения памяти
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize SHA-512 digest");
    }

    for (const auto& val : values) {
        string str = val.toString();
        if (EVP_DigestUpdate(ctx, str.c_str(), str.size()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update SHA-512 digest");
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize SHA-512 digest");
    }

    EVP_MD_CTX_free(ctx);

    stringstream ss;
    for (unsigned int i = 0; i < length; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return BigInt::fromString(ss.str());
}