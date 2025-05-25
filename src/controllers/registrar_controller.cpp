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

class RegistrarController : public drogon::HttpController<RegistrarController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(RegistrarController::registerBallot, "/register_ballot", Post);
    METHOD_LIST_END

    RegistrarController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void registerBallot(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        LOG_INFO << "requested to sign blinded vote";
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

                // Извлекаем данные из JSON
                try {
                    std::string votingId = jsonData["voting_id"].asString();
                    BigInt blindedBallot = BigInt::fromBase64(jsonData["blinded_ballot"].asString());

                    if (blindedBallot > CryptoParams::rsaN) {
                        auto resp = HttpResponse::newHttpResponse();
                        resp->setStatusCode(k400BadRequest);
                        resp->setBody("Blinded ballot is too large");
                        LOG_ERROR << "blinded ballot is too large";
                        callback(resp);
                        return;
                    }

                    BigInt signature =
                        BlindSignature::signBlinded(blindedBallot, CryptoParams::rsaD, CryptoParams::rsaN);

                    Json::Value jsonResponse;
                    jsonResponse["signature"] = signature.toBase64();
                    jsonResponse["success"] = true;

                    auto resp = HttpResponse::newHttpJsonResponse(jsonResponse);
                    LOG_INFO << "signature created successfully";
                    callback(resp);

                } catch (const std::exception& e) {
                    LOG_INFO << "got something7\n";
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