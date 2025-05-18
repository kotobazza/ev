#include <gtest/gtest.h>
#include <vector>

#include "bignum.hpp"
#include "blind_signature.hpp"
#include "pailier.hpp"
#include "zkp.hpp"
#include "merklie_tree.hpp"

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

TEST(PailierCryptography, HardLoad) {
    BigNum p("16404039174607693836360866480585614484544715780109420999587841911243314805066566626825650726886035765629970390895496816430505565496352573586907957772098500424686040693767848777812540038814105744464508531543252694632210497249421920025917799851784883529677022867492269594083416414313340184410386253497558413405372868663939751476246732526677910766901702597914138830472395078921453562041777548374278654042973619250257136324320032842868953709957508447609804087766813722150361073463949285612295115480216832354535797063704116822648914241229246452938261334347254820854775661531314072850103643102893024731790022431913878152973");
    BigNum q("23219647663524783783061952253556607743994047212392754088058700334758166821038715748297093329096091346687489206953245586633859207472304585019035085831471621818114080065451254131268537316510343186272109532617404261517705607623874531045363214982184345676202620527074308299237969642375038272502549434071619968588592191079927360841968177484098371092248391541096285306112533514081769996159382745839407298935713369226168221834895191608536626380517359770089129393662033504744159936114168702882651773086859270354030033904260761678713721640989998845676203111689059473305477120308757035114933199394449803026640152763363652056511");

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

TEST(MerklieTree, SimpleUsage){
    MerkleTree a;
    a.addLeaf("1234");
    a.addLeaf("12345");
    a.addLeaf("12346");
    a.addLeaf("12347");
    a.addLeaf("12348");
    a.addLeaf("12349");

    EXPECT_EQ(a.getRoot(), "5816f1c61fa426728ee36f4275256c45855f1e5df157271d1411693a8ed47c92ab52a3ac8a4e9df6acccaa04405c4ff44710846d7ea0fe30ff364a42effa854d");

    std::string input = "12349";

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha512();
    unsigned char hash[SHA512_DIGEST_LENGTH];
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    std::string hex_ = ss.str();

    auto b = a.getProof(hex_);


    EXPECT_EQ(b.size(), static_cast<size_t>(2));
    EXPECT_EQ(b[0].first, "2de2b0c9e6e6765d8000d0d6532759789eece2c60563a8ce6a0da857d0337b1c754e5606c5dfb73c37697110db0da1123505310b4e9938976c2010b81ef81a1e");
    EXPECT_EQ(b[1].first, "8f54cde82fc63dd8f19047de1e8ba5319df1d45164f5506136b5a25838603a4a950c5a813851c1cf4a8dc2351f3c53a37497ff52889c050009847507511c6d9a");
    EXPECT_EQ(b[0].second, false);
    EXPECT_EQ(b[1].second, false);


    a.removeLeaf(hex_);

    EXPECT_EQ(a.getRoot(), "2a7b999456d176eed8f89997b665b602f193848dd616163f595ff054beda97d3fdd2346f123dc33e8a0c377e1b35bad9daa2c0ee9105fc764c3d4f0ec89cc2b3");


    std::ofstream outFile("merkle_tree.json");

    if (outFile.is_open()) {
        a.serialize(outFile);
        outFile.close();
    } 
}










int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}