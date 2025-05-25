#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium
#include "jwt_auth_filter.h"

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

class UserController : public drogon::HttpController<UserController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(UserController::profilePage, "/user/profile", Get, "JwtAuthFilter");
    METHOD_LIST_END

    UserController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void profilePage(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        std::string login = "alice";
        std::vector<std::pair<std::string, std::string>> votings = {{"123", "Выборы председателя"},
                                                                    {"456", "Голосование по уставу"}};

        HttpViewData data;
        data.insert("login", login);
        data.insert("votings", votings);

        auto resp = drogon::HttpResponse::newHttpViewResponse("profile.csp", data);
        callback(resp);
    }
};
