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
        LOG_INFO << "requested profile page";

        auto token = JwtAuthFilter::getTokenFromRequest(req);
        auto userId = JwtAuthFilter::getUserIdFromToken(token);
        LOG_INFO << "User ID: " << userId;

        auto client = app().getDbClient();
        auto result = client->execSqlSync("SELECT login FROM Users WHERE id = $1", userId);
        if (result.empty()) {
            LOG_ERROR << "User not found";
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::HttpStatusCode::k404NotFound);
            callback(resp);
            return;
        }
        auto login = result[0]["login"].as<std::string>();
        LOG_INFO << "Login: " << login;

        std::vector<std::pair<std::string, std::string>> votings = {{CryptoParams::votingId, "Выборы председателя"}};

        HttpViewData data;
        data.insert("login", login);
        data.insert("votings", votings);

        auto resp = drogon::HttpResponse::newHttpViewResponse("profile.csp", data);
        callback(resp);
    }
};
