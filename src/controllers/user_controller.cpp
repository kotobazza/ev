#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

class UserController : public drogon::HttpController<UserController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(UserController::profilePage, "/user/profile", Get);
    METHOD_LIST_END

    UserController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void profilePage(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
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
                    std::string login = "alice";
                    std::vector<std::pair<std::string, std::string>> votings = {{"123", "Выборы председателя"},
                                                                                {"456", "Голосование по уставу"}};

                    HttpViewData data;
                    data.insert("login", login);
                    data.insert("votings", votings);

                    auto resp = drogon::HttpResponse::newHttpViewResponse("profile.csp", data);
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
