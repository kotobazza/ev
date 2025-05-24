#include "bigint.hpp"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <vector>

/*Operators*/

BigInt BigInt::operator*(const BigInt& rhs) const {
    BigInt result;
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

BigInt BigInt::operator+(const BigInt& rhs) const {
    BigInt result;
    if (!BN_add(result.bn, this->bn, rhs.bn))
        throw std::runtime_error("BN_add failed");
    return result;
}

BigInt BigInt::operator-(const BigInt& rhs) const {
    BigInt result;
    if (!BN_sub(result.bn, this->bn, rhs.bn))
        throw std::runtime_error("BN_sub failed");
    return result;
}

// Деление (целочисленное)
BigInt BigInt::operator/(const BigInt& rhs) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
        throw std::runtime_error("BN_CTX_new failed");

    BigInt result;
    if (!BN_div(result.bn, nullptr, this->bn, rhs.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_div failed");
    }

    BN_CTX_free(ctx);
    return result;
}

// Остаток (mod)
BigInt BigInt::operator%(const BigInt& rhs) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
        throw std::runtime_error("BN_CTX_new failed");

    BigInt result;
    if (!BN_mod(result.bn, this->bn, rhs.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mod failed");
    }

    BN_CTX_free(ctx);
    return result;
}

/*Functions*/

BigInt BigInt::modInverse(const BigInt& mod) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
        throw std::runtime_error("BN_CTX_new failed");

    BigInt inverse;
    if (!BN_mod_inverse(inverse.bn, this->bn, mod.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mod_inverse failed (возможно, числа не взаимно просты)");
    }

    BN_CTX_free(ctx);
    return inverse;
}

BigInt BigInt::modExp(const BigInt& exponent, const BigInt& mod) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
        throw std::runtime_error("BN_CTX_new failed");

    BigInt result;
    if (!BN_mod_exp(result.bn, this->bn, exponent.bn, mod.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mod_exp failed");
    }

    BN_CTX_free(ctx);
    return result;
}

BigInt BigInt::pow(const BigInt& exponent) const {
    if (exponent == BigInt(0)) {
        return BigInt(1);  // a^0 = 1 для любого a ≠ 0
    }

    BigInt result(1);
    BigInt base = *this;
    BigInt exp = exponent;

    // Алгоритм быстрого возведения в степень
    while (exp != BigInt(0)) {
        if (exp % BigInt(2) == BigInt(1)) {  // Если степень нечётная
            result = result * base;
        }
        base = base * base;     // Возводим base в квадрат
        exp = exp / BigInt(2);  // Делим степень на 2
    }

    return result;
}

std::string BigInt::toBase64() const {
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

BigInt BigInt::fromBase64(const std::string& base64Str) {
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
    BigInt result;
    BIGNUM* bn = BN_bin2bn(buf.data(), decodedLen, result.bn);
    if (!bn) {
        BIO_free_all(bio);
        throw std::runtime_error("BN_bin2bn failed");
    }

    BIO_free_all(bio);
    return result;
}

BigInt BigInt::fromString(const std::string& decStr) {
    BigInt result;
    if (!BN_dec2bn(&result.bn, decStr.c_str()))
        throw std::runtime_error("BN_dec2bn failed");
    return result;
}

std::string BigInt::toString() const {
    char* str = BN_bn2dec(bn);
    if (!str)
        throw std::runtime_error("BN_bn2dec failed");
    std::string result(str);
    OPENSSL_free(str);
    return result;
}

BigInt gcd(const BigInt& a, const BigInt& b) {
    BigInt x = a, y = b;
    while (y != BigInt(0)) {
        BigInt temp = y;
        y = x % y;
        x = temp;
    }
    return x;
}

BigInt lcm(const BigInt& a, const BigInt& b) {
    return (a * b) / gcd(a, b);
}