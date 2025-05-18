#pragma once

#include <openssl/bn.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>  // Добавлен для extended_gcd
#include <vector>

class BigNum {
    BIGNUM* bn;

   public:
    BigNum() : bn(BN_new()) {
        if (!bn)
            throw std::runtime_error("BN_new failed");
    }

    explicit BigNum(const std::string& decStr) : BigNum() {
        if (!BN_dec2bn(&bn, decStr.c_str()))
            throw std::runtime_error("BN_dec2bn failed");
    }

    // Конструктор для unsigned int
    explicit BigNum(unsigned int num) : BigNum() {
        if (!BN_set_word(bn, num))
            throw std::runtime_error("BN_set_word failed");
    }

    BigNum(const BigNum& other) : BigNum() {
        if (!BN_copy(bn, other.bn))
            throw std::runtime_error("BN_copy failed");
    }

    BigNum& operator=(const BigNum& other) {
        if (this != &other) {
            if (!BN_copy(bn, other.bn))
                throw std::runtime_error("BN_copy failed");
        }
        return *this;
    }

    bool operator<(const BigNum& rhs) const { return BN_cmp(this->bn, rhs.bn) < 0; }

    bool operator>(const BigNum& rhs) const { return BN_cmp(this->bn, rhs.bn) > 0; }

    bool operator<=(const BigNum& rhs) const { return BN_cmp(this->bn, rhs.bn) <= 0; }

    bool operator>=(const BigNum& rhs) const { return BN_cmp(this->bn, rhs.bn) >= 0; }

    ~BigNum() { BN_free(bn); }

    std::string toString() const {
        char* str = BN_bn2dec(bn);
        std::string result(str);
        OPENSSL_free(str);
        return result;
    }

    // Умножение
    BigNum operator*(const BigNum& rhs) const {
        BigNum result;
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx)
            throw std::runtime_error("BN_CTX_new failed");

        if (!BN_mul(result.bn, this->bn, rhs.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mul failed");
        }

        BN_CTX_free(ctx);
        return result;
    }

    // Сложение
    BigNum operator+(const BigNum& rhs) const {
        BigNum result;
        if (!BN_add(result.bn, this->bn, rhs.bn))
            throw std::runtime_error("BN_add failed");
        return result;
    }

    // Вычитание
    BigNum operator-(const BigNum& rhs) const {
        BigNum result;
        if (!BN_sub(result.bn, this->bn, rhs.bn))
            throw std::runtime_error("BN_sub failed");
        return result;
    }

    // Деление (целочисленное)
    BigNum operator/(const BigNum& rhs) const {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx)
            throw std::runtime_error("BN_CTX_new failed");

        BigNum result;
        if (!BN_div(result.bn, nullptr, this->bn, rhs.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_div failed");
        }

        BN_CTX_free(ctx);
        return result;
    }

    // Остаток (mod)
    BigNum operator%(const BigNum& rhs) const {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx)
            throw std::runtime_error("BN_CTX_new failed");

        BigNum result;
        if (!BN_mod(result.bn, this->bn, rhs.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mod failed");
        }

        BN_CTX_free(ctx);
        return result;
    }

    BigNum modInverse(const BigNum& mod) const {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx)
            throw std::runtime_error("BN_CTX_new failed");

        BigNum inverse;
        if (!BN_mod_inverse(inverse.bn, this->bn, mod.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mod_inverse failed (возможно, числа не взаимно просты)");
        }

        BN_CTX_free(ctx);
        return inverse;
    }

    BigNum modExp(const BigNum& exponent, const BigNum& mod) const {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx)
            throw std::runtime_error("BN_CTX_new failed");

        BigNum result;
        if (!BN_mod_exp(result.bn, this->bn, exponent.bn, mod.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mod_exp failed");
        }

        BN_CTX_free(ctx);
        return result;
    }

    BigNum pow(const BigNum& exponent) const {
        if (exponent == BigNum(0)) {
            return BigNum(1);  // a^0 = 1 для любого a ≠ 0
        }

        BigNum result(1);
        BigNum base = *this;
        BigNum exp = exponent;

        // Алгоритм быстрого возведения в степень
        while (exp != BigNum(0)) {
            if (exp % BigNum(2) == BigNum(1)) {  // Если степень нечётная
                result = result * base;
            }
            base = base * base;     // Возводим base в квадрат
            exp = exp / BigNum(2);  // Делим степень на 2
        }

        return result;
    }

    // Оператор равенства
    bool operator==(const BigNum& rhs) const { return BN_cmp(this->bn, rhs.bn) == 0; }

    // Оператор неравенства
    bool operator!=(const BigNum& rhs) const { return !(*this == rhs); }

    const BIGNUM* raw() const { return bn; }
    BIGNUM* raw() { return bn; }
};

BigNum gcd(const BigNum& a, const BigNum& b) {
    BigNum x = a, y = b;
    while (y != BigNum(0)) {
        BigNum temp = y;
        y = x % y;
        x = temp;
    }
    return x;
}

BigNum lcm(const BigNum& a, const BigNum& b) {
    return (a * b) / gcd(a, b);
}