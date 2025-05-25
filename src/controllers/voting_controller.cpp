#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium

#include "crypto_params.hpp"
#include "openssl/crypto.h"

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

class VotingController : public drogon::HttpController<VotingController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(VotingController::votingPage, "/votings/{1}", Get);
    METHOD_LIST_END

    VotingController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void votingPage(const HttpRequestPtr& req,
                    std::function<void(const HttpResponsePtr&)>&& callback,
                    std::string voting_id) {
        // Сначала пытаемся получить cookie с токеном
        auto cookies = req->cookies();
        auto it = cookies.find("access_token");
        if (it == cookies.end()) {
            // Нет токена — сразу показываем форму входа
            auto resp = HttpResponse::newRedirectionResponse("/user/signin");
            callback(resp);
            return;
        }
        std::string token = it->second;

        // Проверяем токен в Redis
        auto redis_client = app().getRedisClient();
        // Ключ в Redis — "access_token:<token>"
        std::string redis_key = "access_token:" + token;

        redis_client->execCommandAsync(
            [callback](const nosql::RedisResult& result) mutable {
                if (result.isNil() || result.asString().empty()) {
                    // Токен не найден или пустой — показываем форму входа
                    auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                    callback(resp);
                } else {
                    std::vector<std::string> options{"1", "2", "3"};
                    HttpViewData data;

                    data.insert("login", std::string("alice"));
                    data.insert("voting_title", std::string("Voting"));
                    data.insert("voting_question", std::string("Voting?"));
                    data.insert("options", options);  // std::vector<std::string>
                    data.insert("voting_id", std::string("123"));
                    data.insert("crypto_parametr_n", CryptoParams::pailierN.toString());
                    data.insert("options_amount", static_cast<int>(options.size()));
                    data.insert("rsa_public_n", CryptoParams::rsaN.toString());
                    data.insert("rsa_public_e", CryptoParams::rsaE.toString());

                    auto resp = drogon::HttpResponse::newHttpViewResponse("voting.csp", data);
                    callback(resp);
                }
            },
            [callback](const nosql::RedisException& ex) {
                // Ошибка Redis — лучше показать форму входа, но можно логировать
                auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                callback(resp);
            },
            "GET %s", redis_key.c_str());
    }
};
