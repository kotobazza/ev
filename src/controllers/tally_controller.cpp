#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium
#include "bigint.hpp"
#include "blind_signature.hpp"
#include "crypto_params.hpp"
#include "zkp.hpp"

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

class TallyController : public drogon::HttpController<TallyController> {
   public:
    METHOD_LIST_BEGIN
    // Изменяем метод на Post и путь на более подходящий
    ADD_METHOD_TO(TallyController::submitVote, "/voting/submit", Post);
    METHOD_LIST_END

    TallyController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void submitVote(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        LOG_INFO << "requested vote submission";
        // Проверяем JWT токен из куков
        auto cookies = req->cookies();
        auto it = cookies.find("access_token");
        if (it == cookies.end()) {
            auto resp = HttpResponse::newRedirectionResponse("/user/signin");
            callback(resp);
            return;
        }
        std::string token = it->second;

        // Проверяем токен в Redis
        auto redis_client = app().getRedisClient();
        std::string redis_key = "access_token:" + token;

        redis_client->execCommandAsync(
            [req, callback](const nosql::RedisResult& result) mutable {
                if (result.isNil() || result.asString().empty()) {
                    auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                    callback(resp);
                    return;
                }
                LOG_INFO << "checked access tokens";

                // Парсим JSON из тела запроса
                Json::Value jsonData;
                std::string err;
                Json::CharReaderBuilder readerBuilder;
                const std::string jsonStr(req->getBody());
                std::istringstream iss(jsonStr);

                if (!Json::parseFromStream(readerBuilder, iss, &jsonData, &err)) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k400BadRequest);
                    resp->setBody("Invalid JSON: " + err);
                    callback(resp);
                    return;
                }

                try {
                    std::string votingId = jsonData["voting_id"].asString();
                    BigInt encryptedBallot = BigInt::fromBase64(jsonData["encrypted_ballot"].asString());
                    Json::Value zkpProofE = jsonData["zkp_proof_e_vec"];
                    Json::Value zkpProofZ = jsonData["zkp_proof_z_vec"];
                    Json::Value zkpProofA = jsonData["zkp_proof_a_vec"];

                    BigInt signature = BigInt::fromBase64(jsonData["signature"].asString());

                    std::vector<BigInt> eVec, aVec, zVec;

                    for (const auto& num : zkpProofE) {
                        eVec.push_back(BigInt::fromBase64(num.asString()));
                    }

                    for (const auto& num : zkpProofZ) {
                        zVec.push_back(BigInt::fromBase64(num.asString()));
                    }

                    for (const auto& num : zkpProofA) {
                        aVec.push_back(BigInt::fromBase64(num.asString()));
                    }

                    if (encryptedBallot > CryptoParams::rsaN) {
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(false));
                        resp->setStatusCode(HttpStatusCode::k409Conflict);
                        LOG_ERROR << "ballot is bigger than rsa n";
                        callback(resp);
                        return;
                    }

                    if (!BlindSignature::verify(encryptedBallot, signature, CryptoParams::rsaE, CryptoParams::rsaN)) {
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(false));
                        resp->setStatusCode(HttpStatusCode::k409Conflict);
                        LOG_ERROR << "blinding not verified";
                        callback(resp);
                        return;
                    }

                    std::vector<BigInt> msgVariants;
                    for (size_t i = 0; i < eVec.size(); i++) {
                        msgVariants.push_back(BigInt(2).pow(BigInt(30 * i)));
                    }

                    CorrectMessageProof scheme(eVec, zVec, aVec, encryptedBallot, msgVariants, CryptoParams::pailierN);

                    if (scheme.verify()) {
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(true));
                        LOG_INFO << "ballot verified";
                        callback(resp);
                    } else {
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(false));
                        resp->setStatusCode(HttpStatusCode::k409Conflict);
                        LOG_INFO << "ballot not verified";
                        callback(resp);
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR << "error in ballot verification";
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k400BadRequest);
                    resp->setBody(std::string("Missing or invalid fields: ") + e.what());
                    callback(resp);
                }
            },
            [callback](const nosql::RedisException& ex) {
                auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                callback(resp);
            },
            "GET %s", redis_key.c_str());
    }
};