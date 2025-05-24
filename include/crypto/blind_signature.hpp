#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include "bigint.hpp"

class RSAKeyPair {
   public:
    struct PublicKey {
        BigInt e;
        BigInt n;
    };

    struct PrivateKey {
        BigInt d;
        BigInt n;
    };

    PublicKey publicKey;
    PrivateKey privateKey;

    RSAKeyPair(int bits = 512) { generateKeys(bits); }

   private:
    void generateKeys(int bits) {
        // Генерация простых чисел p и q
        BigInt p = generatePrime(bits);
        BigInt q = generatePrime(bits);

        // Убедимся, что p и q разные
        while (p == q) {
            q = generatePrime(bits);
        }

        // Вычисление модуля n и функции Эйлера phi(n)
        BigInt n = p * q;
        BigInt phi = (p - BigInt(1)) * (q - BigInt(1));

        // Обычно e = 65537 (2^16 + 1)
        BigInt e = BigInt::fromString("65537");

        // Проверяем, что e и phi взаимно просты
        while (gcd(e, phi) != BigInt(1)) {
            e = e + BigInt(2);
        }

        // Вычисление секретной экспоненты d
        BigInt d = e.modInverse(phi);

        publicKey = {e, n};
        privateKey = {d, n};
    }

    BigInt generatePrime(int bits) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> distrib(0, 9);

        while (true) {
            // Генерация случайного числа с заданным количеством бит
            std::string numStr;
            for (int i = 0; i < bits / 3.32 + 1; ++i) {  // приблизительное количество цифр
                numStr += std::to_string(distrib(gen));
            }

            BigInt candidate = BigInt::fromString(numStr);

            // Проверка на простоту (упрощенная - в реальном коде нужен тест Миллера-Рабина)
            if (candidate % BigInt(2) != BigInt(0) && isProbablePrime(candidate)) {
                return candidate;
            }
        }
    }

    bool isProbablePrime(const BigInt& n, int k = 5) {
        if (n == BigInt(2) || n == BigInt(3)) {
            return true;
        }
        if (n % BigInt(2) == BigInt(0) || n == BigInt(1)) {
            return false;
        }

        // Представляем n-1 в виде (2^s)*d
        BigInt d = n - BigInt(1);
        BigInt s(0);
        while (d % BigInt(2) == BigInt(0)) {
            d = d / BigInt(2);
            s = s + BigInt(1);
        }

        for (int i = 0; i < k; ++i) {
            BigInt a = randomBigInt(BigInt(2), n - BigInt(2));
            BigInt x = a.modExp(d, n);

            if (x == BigInt(1) || x == n - BigInt(1)) {
                continue;
            }

            bool continueLoop = false;
            for (BigInt j(1); j < s; j = j + BigInt(1)) {
                x = x.modExp(BigInt(2), n);
                if (x == n - BigInt(1)) {
                    continueLoop = true;
                    break;
                }
            }

            if (continueLoop) {
                continue;
            }

            return false;
        }

        return true;
    }

   public:
    static BigInt randomBigInt(const BigInt& min, const BigInt& max) {
        std::random_device rd;
        std::mt19937 gen(rd());
        BigInt range = max - min;

        // Генерация случайного числа в диапазоне [0, range)
        std::string numStr;
        std::string rangeStr = range.toString();
        std::uniform_int_distribution<int> distrib(0, 9);

        for (size_t i = 0; i < rangeStr.size(); ++i) {
            numStr += std::to_string(distrib(gen));
        }

        BigInt randomNum = BigInt::fromString(numStr);
        randomNum = randomNum % range;

        return randomNum + min;
    }
};

class BlindSignature {
   public:
    static std::pair<BigInt, BigInt> blind(const BigInt& message, const BigInt& e, const BigInt& n) {
        // Выбираем случайное r, взаимно простое с n
        BigInt r;
        do {
            r = RSAKeyPair::randomBigInt(BigInt(2), n - BigInt(1));
        } while (gcd(r, n) != BigInt(1));

        // Ослепляем: m' = m * r^e mod n
        BigInt rPowE = r.modExp(e, n);
        BigInt blindedMessage = (message * rPowE) % n;

        return {blindedMessage, r};
    }

    static BigInt signBlinded(const BigInt& blindedMessage, const BigInt& d, const BigInt& n) {
        // Подпись ослепленного сообщения: s' = (m')^d mod n
        return blindedMessage.modExp(d, n);
    }

    static BigInt unblind(const BigInt& blindedSignature, const BigInt& r, const BigInt& n) {
        // Снятие ослепления: s = s' * r^(-1) mod n
        BigInt rInv = r.modInverse(n);
        return (blindedSignature * rInv) % n;
    }

    static bool verify(const BigInt& message, const BigInt& signature, const BigInt& e, const BigInt& n) {
        // Проверка подписи: s^e mod n == m
        BigInt verified = signature.modExp(e, n);
        return verified == message;
    }

    static BigInt messageToBigInt(const std::string& message) {
        // Преобразование строки в BigInt
        BigInt result(0);
        for (char c : message) {
            result = result * BigInt(256) + BigInt(static_cast<unsigned int>(c));
        }
        return result;
    }
};
