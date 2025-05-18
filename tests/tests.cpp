#include <gtest/gtest.h>
#include <vector>

#include "bignum.hpp"
#include "blind_signature.hpp"
#include "pailier.hpp"
#include "zkp.hpp"

TEST(MultiprecisionArithmetic, IsBigNumClassWorks) {
    BigNum a("111");
    EXPECT_EQ(a.toString(), "111");
}

TEST(MultiprecisionArithmetic, SimpleMiltiprecisionOperations) {
    BigNum a("123456789012345678901234567890");
    BigNum b("98765432109876543210");

    BigNum sum = a + b;
    BigNum diff = a - b;
    BigNum prod = a * b;
    BigNum quot = a / b;
    BigNum mod = a % b;

    EXPECT_EQ(sum.toString(), "123456789111111111011111111100");
    EXPECT_EQ(diff.toString(), "123456788913580246791358024680");
    EXPECT_EQ(prod.toString(), "12193263113702179522496570642237463801111263526900");
    EXPECT_EQ(quot.toString(), "1249999988");
    EXPECT_EQ(mod.toString(), "60185185207253086410");
}

TEST(PailierCryptography, SimpleUsecase) {
    BigNum p("838382000974237847921957342377847823774311");
    BigNum q("113011");

    auto [n, lambda_val, g] = generate_keys(p, q);

    std::vector<BigNum> votes{
        BigNum(2).pow(BigNum(30 * 1)), BigNum(2).pow(BigNum(30 * 1)), BigNum(2).pow(BigNum(30 * 1)),
        BigNum(2).pow(BigNum(30 * 1)), BigNum(2).pow(BigNum(30 * 1)),
    };

    std::vector<BigNum> encrypted_votes{};

    for (auto m : votes) {
        encrypted_votes.push_back(encrypt(m, BigNum(113), g, n));
    }

    BigNum encc{1};
    BigNum t{0};
    BigNum nn = n * n;

    for (auto i : encrypted_votes) {
        encc = (encc * i) % nn;
    }

    BigNum decsum = decrypt(encc, g, lambda_val, n);

    EXPECT_EQ(decsum.toString(), "5368709120");
}

TEST(BlindSignature, SimpleTest) {
    try {
        // std::cout << "🔹 Генерация ключей RSA..." << std::endl;
        RSAKeyPair rsa;

        std::string message = "Hello, Blind Signature!";
        // std::cout << "Сообщение: '" << message << "'" << std::endl;

        // Преобразуем сообщение в BigNum
        BigNum m = BlindSignature::messageToBigNum(message);

        // std::cout << "\n🔹 Ослепление сообщения..." << std::endl;
        auto [m_blinded, r] = BlindSignature::blind(m, rsa.publicKey.e, rsa.publicKey.n);

        // std::cout << "\n🔹 Подпись ослеплённого сообщения..." << std::endl;
        BigNum s_blinded = BlindSignature::signBlinded(m_blinded, rsa.privateKey.d, rsa.publicKey.n);

        // std::cout << "\n🔹 Снятие ослепления..." << std::endl;
        BigNum signature = BlindSignature::unblind(s_blinded, r, rsa.publicKey.n);

        // std::cout << "Полученная подпись: " << signature.toString() << std::endl;

        // std::cout << "\n🔹 Проверка подписи..." << std::endl;
        [[maybe_unused]] bool is_valid = BlindSignature::verify(m, signature, rsa.publicKey.e, rsa.publicKey.n);
        // std::cout << "Подпись " << (is_valid ? "верна" : "неверна") << "!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

TEST(ZKP, SimpleTest) {
    try {
        // Генерация ключей
        BigNum p("838382000974237847921957342377847823774311");
        BigNum q("113011");
        BigNum n = p * q;
        BigNum lambdaVal = lcm(p - BigNum(1), q - BigNum(1));
        BigNum g = n + BigNum(1);

        // Варианты голосов (должны быть уникальными и достаточно большими)
        std::vector<BigNum> voteVariants;
        for (int i = 0; i < 4; ++i) {
            voteVariants.push_back(BigNum(2).pow(BigNum(30 * i)));
        }

        // Тестовые голоса (должны быть из voteVariants)
        std::vector<BigNum> votes;
        for (int i = 0; i < 5; ++i) {
            votes.push_back(BigNum(2).pow(BigNum(30 * 1)));
        }

        // Проверка, что все голоса из допустимых вариантов
        /*
        for (const auto& vote : votes) {
            if (std::find(voteVariants.begin(), voteVariants.end(), vote) == voteVariants.end()) {
                throw std::runtime_error("Голос не входит в допустимые варианты");
            }
        }
        */

        // Процесс голосования с доказательствами
        std::vector<BigNum> encryptedVotes;
        std::vector<CorrectMessageProof> proofs;

        for (const auto& m : votes) {
            // Генерация доказательства
            CorrectMessageProof proof = CorrectMessageProof::prove(n, voteVariants, m);
            proofs.push_back(proof);

            // Проверка доказательства (это будет делать получатель)
            if (!proof.verify()) {
                throw std::runtime_error("Доказательство не прошло проверку");
            }

            // Сохраняем зашифрованный голос
            encryptedVotes.push_back(proof.getCiphertext());

            std::cout << "Зашифрованный голос: " << proof.getCiphertext().toString() << std::endl;
        }

        // Проверка всех бюллетеней перед подсчетом
        std::cout << "Проверка всех бюллетеней перед подсчетом:" << std::endl;
        for (size_t i = 0; i < proofs.size(); ++i) {
            if (!proofs[i].verify()) {
                std::cout << "Бюллетень " << i << " не прошел проверку!" << std::endl;
            } else {
                std::cout << "Бюллетень " << i << " корректен" << std::endl;
            }
        }

        // Подсчет голосов (гомоморфное сложение)
        BigNum encryptedSum(1);
        for (const auto& vote : encryptedVotes) {
            encryptedSum = (encryptedSum * vote) % (n * n);
        }

        // Расшифровка суммы
        BigNum numerator = ((encryptedSum.modExp(lambdaVal, n * n) - BigNum(1)) / n) % n;
        BigNum denominator = ((g.modExp(lambdaVal, n * n) - BigNum(1)) / n) % n;
        BigNum decryptedSum = (numerator * denominator.modInverse(n)) % n;

        std::cout << "Итоговый результат: " << decryptedSum.toString() << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}