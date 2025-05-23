#include "bignum.hpp"
#include <vector>
#include <random>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <algorithm>
#include <memory>

class CorrectMessageProof {
private:
    std::vector<BigNum> e_vec;
    std::vector<BigNum> z_vec;
    std::vector<BigNum> a_vec;
    BigNum ciphertext;
    std::vector<BigNum> valid_messages;
    BigNum n;
    BigNum nn;

    // Вспомогательная функция для вычисления хеша с использованием EVP
    static BigNum computeDigest(const std::vector<BigNum>& values) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        const EVP_MD* md = EVP_sha256();
        
        if (!mdctx || !EVP_DigestInit_ex(mdctx, md, nullptr)) {
            if (mdctx) EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to initialize hash context");
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
        
        EVP_MD_CTX_free(mdctx);
        
        BigNum result;
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, result.raw());
        return result;
    }

    // Генерация случайного числа в диапазоне [min, max)
    static BigNum randomInRange(const BigNum& min, const BigNum& max) {
        BigNum range = max - min;
        BigNum randomNum;
        
        BN_CTX* ctx = BN_CTX_new();
        BN_rand_range(randomNum.raw(), range.raw());
        randomNum = randomNum + min;
        BN_CTX_free(ctx);
        
        return randomNum;
    }

public:
    CorrectMessageProof(const std::vector<BigNum>& eVec, const std::vector<BigNum>& zVec,
                       const std::vector<BigNum>& aVec, const BigNum& cipher,
                       const std::vector<BigNum>& validMsgs, const BigNum& n)
        : e_vec(eVec), z_vec(zVec), a_vec(aVec), ciphertext(cipher),
          valid_messages(validMsgs), n(n), nn(n * n) {}

    static CorrectMessageProof prove(const BigNum& n, const std::vector<BigNum>& validMessages,
                                   const BigNum& messageToEncrypt) {
        BigNum nn = n * n;
        size_t numOfMessages = validMessages.size();
        
        // Генерация случайного r и шифрование сообщения
        BigNum r;
        do {
            r = randomInRange(BigNum(2), n);
        } while (gcd(r, n) != BigNum(1));
        
        BigNum g = n + BigNum(1);  // Стандартное значение g для Paillier
        BigNum ciphertext = (g.modExp(messageToEncrypt, nn) * r.modExp(n, nn)) % nn;
        
        // Вычисление u_i для каждого допустимого сообщения
        std::vector<BigNum> uiVec;
        for (const auto& m : validMessages) {
            BigNum gm = (m * n + BigNum(1)) % nn;
            BigNum gmInv = gm.modInverse(nn);
            BigNum ui = (ciphertext * gmInv) % nn;
            uiVec.push_back(ui);
        }
        
        // Генерация случайных e_j и z_j для всех сообщений, кроме истинного
        const int B = 256;  // Параметр безопасности
        BigNum twoToB = BigNum(2).pow(BigNum(B));
        
        std::vector<BigNum> eiVec;
        std::vector<BigNum> ziVec;
        for (size_t i = 0; i < numOfMessages - 1; ++i) {
            eiVec.push_back(randomInRange(BigNum(0), twoToB));
            ziVec.push_back(randomInRange(BigNum(2), n));
        }
        
        // Генерация случайного w
        BigNum w = randomInRange(BigNum(2), n);
        
        // Находим индекс истинного сообщения
        size_t trueIndex = std::distance(validMessages.begin(),
            std::find(validMessages.begin(), validMessages.end(), messageToEncrypt));
        
        // Вычисляем a_i для каждого сообщения
        std::vector<BigNum> aiVec;
        size_t j = 0;
        for (size_t i = 0; i < numOfMessages; ++i) {
            if (i == trueIndex) {
                BigNum ai = w.modExp(n, nn);
                aiVec.push_back(ai);
            } else {
                BigNum ziN = ziVec[j].modExp(n, nn);
                BigNum uiEi = uiVec[i].modExp(eiVec[j], nn);
                BigNum uiEiInv = uiEi.modInverse(nn);
                BigNum ai = (ziN * uiEiInv) % nn;
                aiVec.push_back(ai);
                j++;
            }
        }
        
        // Вычисляем challenge (chal)
        BigNum chal = computeDigest(aiVec) % twoToB;
        
        // Вычисляем e_i для истинного сообщения
        BigNum eiSum = BigNum(0);
        for (const auto& ei : eiVec) {
            eiSum = (eiSum + ei) % twoToB;
        }
        BigNum ei = (chal - eiSum + twoToB) % twoToB;
        
        // Вычисляем z_i для истинного сообщения
        BigNum riEi = r.modExp(ei, n);
        BigNum zi = (w * riEi) % n;
        
        // Собираем полные векторы e_vec и z_vec
        std::vector<BigNum> eVec;
        std::vector<BigNum> zVec;
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
        BigNum twoToB = BigNum(2).pow(BigNum(B));
        
        // Проверка суммы e_i
        BigNum chal = computeDigest(a_vec) % twoToB;
        BigNum eiSum = BigNum(0);
        for (const auto& e : e_vec) {
            eiSum = (eiSum + e) % twoToB;
        }
        if (chal != eiSum) {
            return false;
        }
        
        // Вычисление u_i для каждого допустимого сообщения
        std::vector<BigNum> uiVec;
        for (const auto& m : valid_messages) {
            BigNum gm = (m * n + BigNum(1)) % nn;
            BigNum gmInv = gm.modInverse(nn);
            BigNum ui = (ciphertext * gmInv) % nn;
            uiVec.push_back(ui);
        }
        
        // Проверка каждого уравнения z_i^n ≡ a_i * u_i^e_i mod n²
        for (size_t i = 0; i < numOfMessages; ++i) {
            BigNum ziN = z_vec[i].modExp(n, nn);
            BigNum uiEi = uiVec[i].modExp(e_vec[i], nn);
            BigNum rightSide = (a_vec[i] * uiEi) % nn;
            if (ziN != rightSide) {
                return false;
            }
        }
        
        return true;
    }

    // Геттеры для доступа к данным
    const BigNum& getCiphertext() const { return ciphertext; }
    const std::vector<BigNum>& getValidMessages() const { return valid_messages; }
};

