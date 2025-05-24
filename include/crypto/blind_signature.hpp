#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include "bignum.hpp"

class RSAKeyPair {
   public:
    struct PublicKey {
        BigNum e;
        BigNum n;
    };

    struct PrivateKey {
        BigNum d;
        BigNum n;
    };

    PublicKey publicKey;
    PrivateKey privateKey;

    RSAKeyPair(int bits = 512) { generateKeys(bits); }

   private:
    void generateKeys(int bits) {
        // Генерация простых чисел p и q
        BigNum p = generatePrime(bits);
        BigNum q = generatePrime(bits);

        // Убедимся, что p и q разные
        while (p == q) {
            q = generatePrime(bits);
        }

        // Вычисление модуля n и функции Эйлера phi(n)
        BigNum n = p * q;
        BigNum phi = (p - BigNum(1)) * (q - BigNum(1));

        // Обычно e = 65537 (2^16 + 1)
        BigNum e = BigNum::fromString("65537");

        // Проверяем, что e и phi взаимно просты
        while (gcd(e, phi) != BigNum(1)) {
            e = e + BigNum(2);
        }

        // Вычисление секретной экспоненты d
        BigNum d = e.modInverse(phi);

        publicKey = {e, n};
        privateKey = {d, n};
    }

    BigNum generatePrime(int bits) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> distrib(0, 9);

        while (true) {
            // Генерация случайного числа с заданным количеством бит
            std::string numStr;
            for (int i = 0; i < bits / 3.32 + 1; ++i) {  // приблизительное количество цифр
                numStr += std::to_string(distrib(gen));
            }

            BigNum candidate = BigNum::fromString(numStr);

            // Проверка на простоту (упрощенная - в реальном коде нужен тест Миллера-Рабина)
            if (candidate % BigNum(2) != BigNum(0) && isProbablePrime(candidate)) {
                return candidate;
            }
        }
    }

    bool isProbablePrime(const BigNum& n, int k = 5) {
        if (n == BigNum(2) || n == BigNum(3)) {
            return true;
        }
        if (n % BigNum(2) == BigNum(0) || n == BigNum(1)) {
            return false;
        }

        // Представляем n-1 в виде (2^s)*d
        BigNum d = n - BigNum(1);
        BigNum s(0);
        while (d % BigNum(2) == BigNum(0)) {
            d = d / BigNum(2);
            s = s + BigNum(1);
        }

        for (int i = 0; i < k; ++i) {
            BigNum a = randomBigNum(BigNum(2), n - BigNum(2));
            BigNum x = a.modExp(d, n);

            if (x == BigNum(1) || x == n - BigNum(1)) {
                continue;
            }

            bool continueLoop = false;
            for (BigNum j(1); j < s; j = j + BigNum(1)) {
                x = x.modExp(BigNum(2), n);
                if (x == n - BigNum(1)) {
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
    static BigNum randomBigNum(const BigNum& min, const BigNum& max) {
        std::random_device rd;
        std::mt19937 gen(rd());
        BigNum range = max - min;

        // Генерация случайного числа в диапазоне [0, range)
        std::string numStr;
        std::string rangeStr = range.toString();
        std::uniform_int_distribution<int> distrib(0, 9);

        for (size_t i = 0; i < rangeStr.size(); ++i) {
            numStr += std::to_string(distrib(gen));
        }

        BigNum randomNum = BigNum::fromString(numStr);
        randomNum = randomNum % range;

        return randomNum + min;
    }
};

class BlindSignature {
   public:
    static std::pair<BigNum, BigNum> blind(const BigNum& message, const BigNum& e, const BigNum& n) {
        // Выбираем случайное r, взаимно простое с n
        BigNum r;
        do {
            r = RSAKeyPair::randomBigNum(BigNum(2), n - BigNum(1));
        } while (gcd(r, n) != BigNum(1));

        // Ослепляем: m' = m * r^e mod n
        BigNum rPowE = r.modExp(e, n);
        BigNum blindedMessage = (message * rPowE) % n;

        return {blindedMessage, r};
    }

    static BigNum signBlinded(const BigNum& blindedMessage, const BigNum& d, const BigNum& n) {
        // Подпись ослепленного сообщения: s' = (m')^d mod n
        return blindedMessage.modExp(d, n);
    }

    static BigNum unblind(const BigNum& blindedSignature, const BigNum& r, const BigNum& n) {
        // Снятие ослепления: s = s' * r^(-1) mod n
        BigNum rInv = r.modInverse(n);
        return (blindedSignature * rInv) % n;
    }

    static bool verify(const BigNum& message, const BigNum& signature, const BigNum& e, const BigNum& n) {
        // Проверка подписи: s^e mod n == m
        BigNum verified = signature.modExp(e, n);
        return verified == message;
    }

    static BigNum messageToBigNum(const std::string& message) {
        // Преобразование строки в BigNum
        BigNum result(0);
        for (char c : message) {
            result = result * BigNum(256) + BigNum(static_cast<unsigned int>(c));
        }
        return result;
    }
};
