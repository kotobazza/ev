#include <openssl/evp.h>
#include <openssl/sha.h>
#include <algorithm>
#include <iostream>
#include <memory>
#include <random>
#include <vector>
#include "bigint.hpp"

class CorrectMessageProof {
   private:
    std::vector<BigInt> e_vec;
    std::vector<BigInt> z_vec;
    std::vector<BigInt> a_vec;
    BigInt ciphertext;
    std::vector<BigInt> valid_messages;
    BigInt n;
    BigInt nn;

    // Вспомогательная функция для вычисления хеша с использованием EVP
    static BigInt computeDigest(const std::vector<BigInt>& values) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        const EVP_MD* md = EVP_sha256();

        if (!mdctx || !EVP_DigestInit_ex(mdctx, md, nullptr)) {
            if (mdctx)
                EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to initialize hash context");
        }

        std::cout << "C++ hashing values:" << std::endl;
        for (const auto& val : values) {
            std::cout << val.toString() << std::endl;
        }

        for (const auto& val : values) {
            std::string str = val.toString();
            if (!EVP_DigestUpdate(mdctx, str.c_str(), str.size())) {
                EVP_MD_CTX_free(mdctx);
                throw std::runtime_error("Failed to update hash");
            }
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned int len;
        if (!EVP_DigestFinal_ex(mdctx, hash, &len)) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to finalize hash");
        }

        std::string hexHash;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            char hex[3];
            sprintf(hex, "%02x", hash[i]);
            hexHash += hex;
        }
        std::cout << "C++ hash hex: " << hexHash << std::endl;

        EVP_MD_CTX_free(mdctx);

        BigInt result;
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, result.raw());
        std::cout << "C++ final result: " << result.toString() << std::endl;
        return result;
    }

    // Генерация случайного числа в диапазоне [min, max)
    static BigInt randomInRange(const BigInt& min, const BigInt& max) {
        BigInt range = max - min;
        BigInt randomNum;

        BN_CTX* ctx = BN_CTX_new();
        BN_rand_range(randomNum.raw(), range.raw());
        randomNum = randomNum + min;
        BN_CTX_free(ctx);

        return randomNum;
    }

   public:
    // Оригинальный конструктор
    CorrectMessageProof(const std::vector<BigInt>& eVec,
                        const std::vector<BigInt>& zVec,
                        const std::vector<BigInt>& aVec,
                        const BigInt& cipher,
                        const std::vector<BigInt>& validMsgs,
                        const BigInt& n)
        : e_vec(eVec), z_vec(zVec), a_vec(aVec), ciphertext(cipher), valid_messages(validMsgs), n(n), nn(n * n) {}

    CorrectMessageProof(const BigInt& r,
                        const std::vector<BigInt>& ziVec,
                        const std::vector<BigInt>& eiVec,
                        const BigInt& w,
                        const BigInt& encrypted_mesg,
                        size_t index,
                        const std::vector<BigInt>& validMsgs,
                        const BigInt& modulus_n)
        : ciphertext(encrypted_mesg), valid_messages(validMsgs), n(modulus_n), nn(modulus_n * modulus_n) {
        // Проверяем, что количество zi соответствует количеству сообщений минус 1

        BigInt twoToB = BigInt(2).pow(BigInt(256));  // Параметр безопасности B=256
        BigInt g = n + BigInt(1);                    // Стандартное значение g для Paillier

        // Вычисляем u_i для каждого допустимого сообщения
        std::vector<BigInt> uiVec;
        for (const auto& m : valid_messages) {
            BigInt gm = (n + BigInt(1)).modExp(m, nn);
            BigInt gmInv = gm.modInverse(nn);
            BigInt ui = (ciphertext * gmInv) % nn;
            uiVec.push_back(ui);
        }

        // Вычисляем a_i для каждого сообщения
        a_vec.resize(valid_messages.size());
        e_vec.resize(valid_messages.size());
        z_vec.resize(valid_messages.size());

        // Находим индекс истинного сообщения (которое было зашифровано)
        size_t trueIndex = index;

        // Заполняем векторы e_vec и z_vec
        size_t j = 0;
        for (size_t i = 0; i < valid_messages.size(); ++i) {
            if (i == trueIndex) {
                // Для истинного сообщения
                BigInt ai = w.modExp(n, nn);
                a_vec[i] = ai;

                // Вычисляем e_i для истинного сообщения
                BigInt eiSum = BigInt(0);
                for (const auto& ei : eiVec) {
                    eiSum = (eiSum + ei) % twoToB;
                }

                std::cout << "eisum:" << eiSum.toString() << "\n";
                std::cout << "twotob:" << twoToB.toString() << "\n";

                // ОШИБКА ВОТ ЗДЕСЯ
                BigInt chal = computeDigest(a_vec) % twoToB;
                std::cout << "chal:" << chal.toString() << "\n";

                BigInt ei = (chal - eiSum + twoToB) % twoToB;
                std::cout << "ei:" << ei.toString() << "\n";
                e_vec[i] = ei;

                // Вычисляем z_i для истинного сообщения
                BigInt riEi = r.modExp(ei, n);
                BigInt zi = (w * riEi) % n;
                z_vec[i] = zi;
            } else {
                // Для других сообщений
                a_vec[i] = (ziVec[j].modExp(n, nn) * uiVec[i].modExp(eiVec[j], nn).modInverse(nn)) % nn;
                e_vec[i] = eiVec[j];
                z_vec[i] = ziVec[j];
                j++;
            }
        }
    }

    static CorrectMessageProof prove(const BigInt& n,
                                     const std::vector<BigInt>& validMessages,
                                     const BigInt& messageToEncrypt) {
        BigInt nn = n * n;
        size_t numOfMessages = validMessages.size();

        // Генерация случайного r и шифрование сообщения
        BigInt r;
        do {
            r = randomInRange(BigInt(2), n);
        } while (gcd(r, n) != BigInt(1));

        BigInt g = n + BigInt(1);  // Стандартное значение g для Paillier
        BigInt ciphertext = (g.modExp(messageToEncrypt, nn) * r.modExp(n, nn)) % nn;

        // Вычисление u_i для каждого допустимого сообщения
        std::vector<BigInt> uiVec;
        for (const auto& m : validMessages) {
            BigInt gm = (n + BigInt(1)).modExp(m, nn);
            BigInt gmInv = gm.modInverse(nn);
            BigInt ui = (ciphertext * gmInv) % nn;
            uiVec.push_back(ui);
        }

        // Генерация случайных e_j и z_j для всех сообщений, кроме истинного
        const int B = 256;  // Параметр безопасности
        BigInt twoToB = BigInt(2).pow(BigInt(B));

        std::vector<BigInt> eiVec;
        std::vector<BigInt> ziVec;
        for (size_t i = 0; i < numOfMessages - 1; ++i) {
            eiVec.push_back(randomInRange(BigInt(0), twoToB));
            ziVec.push_back(randomInRange(BigInt(2), n));
        }

        // Генерация случайного w
        BigInt w = randomInRange(BigInt(2), n);

        // Находим индекс истинного сообщения
        size_t trueIndex = std::distance(validMessages.begin(),
                                         std::find(validMessages.begin(), validMessages.end(), messageToEncrypt));

        // Вычисляем a_i для каждого сообщения
        std::vector<BigInt> aiVec;
        size_t j = 0;
        for (size_t i = 0; i < numOfMessages; ++i) {
            if (i == trueIndex) {
                BigInt ai = w.modExp(n, nn);
                aiVec.push_back(ai);
            } else {
                BigInt ziN = ziVec[j].modExp(n, nn);
                BigInt uiEi = uiVec[i].modExp(eiVec[j], nn);
                BigInt uiEiInv = uiEi.modInverse(nn);
                BigInt ai = (ziN * uiEiInv) % nn;
                aiVec.push_back(ai);
                j++;
            }
        }

        // Вычисляем challenge (chal)
        BigInt chal = computeDigest(aiVec) % twoToB;

        // Вычисляем e_i для истинного сообщения
        BigInt eiSum = BigInt(0);
        for (const auto& ei : eiVec) {
            eiSum = (eiSum + ei) % twoToB;
        }
        BigInt ei = (chal - eiSum + twoToB) % twoToB;

        // Вычисляем z_i для истинного сообщения
        BigInt riEi = r.modExp(ei, n);
        BigInt zi = (w * riEi) % n;

        // Собираем полные векторы e_vec и z_vec
        std::vector<BigInt> eVec;
        std::vector<BigInt> zVec;
        j = 0;
        for (size_t i = 0; i < numOfMessages; ++i) {
            if (i == trueIndex) {
                eVec.push_back(ei);
                zVec.push_back(zi);
            } else {
                eVec.push_back(eiVec[j]);
                zVec.push_back(ziVec[j]);
                j++;
            }
        }

        return CorrectMessageProof(eVec, zVec, aiVec, ciphertext, validMessages, n);
    }

    bool verify() const {
        size_t numOfMessages = valid_messages.size();
        const int B = 256;
        BigInt twoToB = BigInt(2).pow(BigInt(B));
        std::cout << "twoToB:" << twoToB.toString() << "\n";

        // Проверка суммы e_i
        BigInt chal = computeDigest(a_vec) % twoToB;
        std::cout << "chal:" << chal.toString() << "\n";
        BigInt eiSum = BigInt(0);

        for (const auto& e : e_vec) {
            std::cout << "e:" << e.toString() << "\n";
            eiSum = (eiSum + e) % twoToB;
        }
        std::cout << "eiSum:" << eiSum.toString() << "\n";
        if (chal != eiSum) {
            return false;
        }

        std::cout << "пройдено\n";

        // Вычисление u_i для каждого допустимого сообщения
        std::vector<BigInt> uiVec;
        for (const auto& m : valid_messages) {
            BigInt gm = (n + BigInt(1)).modExp(m, nn);
            BigInt gmInv = gm.modInverse(nn);
            BigInt ui = (ciphertext * gmInv) % nn;
            uiVec.push_back(ui);
        }

        // Проверка каждого уравнения z_i^n ≡ a_i * u_i^e_i mod n²
        for (size_t i = 0; i < numOfMessages; i++) {
            BigInt ziN = z_vec[i].modExp(n, nn);
            BigInt uiEi = uiVec[i].modExp(e_vec[i], nn);
            BigInt rightSide = (a_vec[i] * uiEi) % nn;

            std::cout << "uiEi" << uiEi.toString() << "\n";
            std::cout << "ziN:" << ziN.toString() << "\n"
                      << "rightSide:" << rightSide.toString() << "\n";
            if (ziN != rightSide) {
                return false;
            }
        }

        return true;
    }

    // Геттеры для доступа к данным
    const BigInt& getCiphertext() const { return ciphertext; }
    const std::vector<BigInt>& getValidMessages() const { return valid_messages; }
    const std::vector<BigInt>& getE() const { return e_vec; }
    const std::vector<BigInt>& getZ() const { return z_vec; }
    const std::vector<BigInt>& getA() const { return a_vec; }
};