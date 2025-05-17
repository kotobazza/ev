#include <gtest/gtest.h>
#include <vector>

#include "bignum.hpp"
#include "pailier.hpp"

TEST(MultiprecisionArithmetic, IsBigNumClassWorks){
    BigNum a("111");
    EXPECT_EQ(a.toString(), "111");
}

TEST(MultiprecisionArithmetic, SimpleMiltiprecisionOperations){
    BigNum a("123456789012345678901234567890");
    BigNum b("98765432109876543210");

    BigNum sum = a + b;
    BigNum diff = a - b;
    BigNum prod = a * b;
    BigNum quot = a / b;
    BigNum mod  = a % b;

    EXPECT_EQ(sum.toString(), "123456789111111111011111111100");
    EXPECT_EQ(diff.toString(), "123456788913580246791358024680");
    EXPECT_EQ(prod.toString(), "12193263113702179522496570642237463801111263526900");
    EXPECT_EQ(quot.toString(), "1249999988");
    EXPECT_EQ(mod.toString(), "60185185207253086410");
}


TEST(PailierCryptography, SimpleUsecase){
    BigNum p("838382000974237847921957342377847823774311");
    BigNum q("113011");
    
    auto [n, lambda_val, g] = generate_keys(p, q);

    std::vector<BigNum> votes {BigNum(2).pow(BigNum(30*1)), BigNum(2).pow(BigNum(30*1)), BigNum(2).pow(BigNum(30*1)), BigNum(2).pow(BigNum(30*1)), BigNum(2).pow(BigNum(30*1)),};

    std::vector<BigNum> encrypted_votes{};

    for(auto m: votes){
        encrypted_votes.push_back(encrypt(m, BigNum(113), g, n));
    }


    BigNum encc{1};
    BigNum t{0};
    BigNum nn = n*n;

    for(auto i: encrypted_votes){
        encc = (encc*i) % nn;
    }

    BigNum decsum = decrypt(encc, g, lambda_val, n);

    EXPECT_EQ(decsum.toString(), "5368709120");
}












int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}