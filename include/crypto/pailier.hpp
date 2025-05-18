#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include "bignum.hpp"
#include <openssl/evp.h>

using namespace std;



BigNum L(const BigNum& x, const BigNum& n) {
    return (x - BigNum(1)) / n;
}

tuple<BigNum, BigNum, BigNum> generate_keys(const BigNum& p, const BigNum& q) {
    BigNum n = p * q;
    BigNum lambda = lcm(p - BigNum(1), q - BigNum(1));
    BigNum g = n + BigNum(1);
    return {n, lambda, g};
}

BigNum encrypt(const BigNum& m, const BigNum& r, const BigNum& g, const BigNum& n) {
    BigNum nn = n * n;
    return (g.modExp(m, nn) * r.modExp(n, nn)) % nn;
}

BigNum decrypt(const BigNum& c, const BigNum& g, const BigNum& lambda, const BigNum& n) {
    BigNum nn = n * n;
    BigNum numerator = L(c.modExp(lambda, nn), n);
    BigNum denominator = L(g.modExp(lambda, nn), n);
    return (numerator * denominator.modInverse(n)) % n;
}

BigNum compute_digest(const vector<BigNum>& values) {
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
    
    return BigNum(ss.str());
}