#pragma once

#include <openssl/bn.h>
#include <stdexcept>
#include <string>

class BigInt {
   private:
    BIGNUM* bn;

   public:
    BigInt() : bn(BN_new()) {
        if (!bn)
            throw std::runtime_error("BN_new failed");
    };
    BigInt(unsigned int num) : BigInt() {
        if (!BN_set_word(bn, num))
            throw std::runtime_error("BN_set_word failed");
    }

    BigInt(const BigInt& other) : BigInt() {
        if (!BN_copy(bn, other.bn))
            throw std::runtime_error("BN_copy failed");
    }

    static BigInt fromBase64(const std::string& base64Str);
    static BigInt fromString(const std::string& decStr);

    BigInt& operator=(const BigInt& other) {
        if (this != &other) {
            if (!BN_copy(bn, other.bn))
                throw std::runtime_error("BN_copy failed");
        }
        return *this;
    }

    ~BigInt() { BN_free(bn); };

    BIGNUM* raw() { return bn; }
    const BIGNUM* raw() const { return bn; }

    /*Operators*/
    BigInt operator*(const BigInt& rhs) const;
    BigInt operator+(const BigInt& rhs) const;
    BigInt operator-(const BigInt& rhs) const;
    BigInt operator/(const BigInt& rhs) const;
    BigInt operator%(const BigInt& rhs) const;
    bool operator==(const BigInt& other) const { return BN_cmp(bn, other.bn) == 0; }

    bool operator!=(const BigInt& other) const { return !(*this == other); }

    bool operator<(const BigInt& other) const { return BN_cmp(bn, other.bn) < 0; }

    bool operator>(const BigInt& other) const { return BN_cmp(bn, other.bn) > 0; }

    bool operator<=(const BigInt& other) const { return BN_cmp(bn, other.bn) <= 0; }

    bool operator>=(const BigInt& other) const { return BN_cmp(bn, other.bn) >= 0; }

    BigInt modInverse(const BigInt& mod) const;

    BigInt modExp(const BigInt& exponent, const BigInt& mod) const;

    BigInt pow(const BigInt& exponent) const;

    std::string toBase64() const;
    std::string toString() const;
};

BigInt gcd(const BigInt& a, const BigInt& b);

BigInt lcm(const BigInt& a, const BigInt& b);