#pragma once

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <tuple>  // Добавлен для extended_gcd
#include <vector>

class BigNum {
   private:
    BIGNUM* bn;

   public:
    // Получить указатель на внутренний BIGNUM для использования в функциях OpenSSL
    BIGNUM* raw() { return bn; }
    const BIGNUM* raw() const { return bn; }

    BigNum() : bn(BN_new()) {
        if (!bn)
            throw std::runtime_error("BN_new failed");
    }

    BigNum(unsigned int num) : BigNum() {
        if (!BN_set_word(bn, num))
            throw std::runtime_error("BN_set_word failed");
    }

    BigNum(const BigNum& other) : BigNum() {
        if (!BN_copy(bn, other.bn))
            throw std::runtime_error("BN_copy failed");
    }

    ~BigNum() { BN_free(bn); }

    BigNum& operator=(const BigNum& other) {
        if (this != &other) {
            if (!BN_copy(bn, other.bn))
                throw std::runtime_error("BN_copy failed");
        }
        return *this;
    }

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

    std::string toBase64() const {
        // Получаем бинарное представление числа
        int size = BN_num_bytes(bn);
        std::vector<unsigned char> buf(size);
        BN_bn2bin(bn, buf.data());

        // Создаем BIO chain для Base64 кодирования
        BIO *bio, *b64;
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        // Отключаем добавление новых строк (по умолчанию Base64 BIO добавляет их)
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        // Записываем данные
        BIO_write(bio, buf.data(), buf.size());
        BIO_flush(bio);

        // Получаем результат
        char* base64Data;
        long base64Length = BIO_get_mem_data(bio, &base64Data);
        std::string result(base64Data, base64Length);

        // Освобождаем ресурсы
        BIO_free_all(bio);

        return result;
    }

    static BigNum fromBase64(const std::string& base64Str) {
        // Создаем BIO chain для Base64 декодирования
        BIO *bio, *b64;
        bio = BIO_new_mem_buf(base64Str.data(), base64Str.size());
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        // Отключаем ожидание новых строк
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        // Читаем декодированные данные
        std::vector<unsigned char> buf(base64Str.size());  // Максимально возможный размер
        int decodedLen = BIO_read(bio, buf.data(), buf.size());

        if (decodedLen < 0) {
            BIO_free_all(bio);
            throw std::runtime_error("Base64 decoding failed");
        }

        // Создаем BigNum из бинарных данных
        BigNum result;
        BIGNUM* bn = BN_bin2bn(buf.data(), decodedLen, result.bn);
        if (!bn) {
            BIO_free_all(bio);
            throw std::runtime_error("BN_bin2bn failed");
        }

        BIO_free_all(bio);
        return result;
    }

    static BigNum fromString(const std::string& decStr) {
        BigNum result;
        if (!BN_dec2bn(&result.bn, decStr.c_str()))
            throw std::runtime_error("BN_dec2bn failed");
        return result;
    }

    std::string toString() const {
        char* str = BN_bn2dec(bn);
        if (!str)
            throw std::runtime_error("BN_bn2dec failed");
        std::string result(str);
        OPENSSL_free(str);
        return result;
    }

    bool operator==(const BigNum& other) const { return BN_cmp(bn, other.bn) == 0; }

    bool operator!=(const BigNum& other) const { return !(*this == other); }

    bool operator<(const BigNum& other) const { return BN_cmp(bn, other.bn) < 0; }

    bool operator>(const BigNum& other) const { return BN_cmp(bn, other.bn) > 0; }

    bool operator<=(const BigNum& other) const { return BN_cmp(bn, other.bn) <= 0; }

    bool operator>=(const BigNum& other) const { return BN_cmp(bn, other.bn) >= 0; }
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