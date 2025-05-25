#include "jwt_auth_filter.h"
#include <drogon/HttpResponse.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <future>
#include "crypto_params.hpp"
#include "drogon/nosql/RedisException.h"
#include "drogon/nosql/RedisResult.h"

using traits = jwt::traits::open_source_parsers_jsoncpp;

JwtAuthFilter::JwtAuthFilter() {}

std::string JwtAuthFilter::createToken(int userId) {
    LOG_INFO << "Creating token for user ID: " << userId;

    auto now = std::chrono::system_clock::now();
    auto expires = now + std::chrono::minutes(CryptoParams::jwtAuthTokenValidityMinutes);

    auto token = jwt::create<traits>()
                     .set_type("JWT")
                     .set_issuer(CryptoParams::jwtIssuer)
                     .set_payload_claim("user_id", jwt::basic_claim<traits>(std::to_string(userId)))
                     .set_issued_at(now)
                     .set_expires_at(expires)
                     .sign(jwt::algorithm::hs256{CryptoParams::jwtSecret});

    if (!storeTokenInRedis(token, CryptoParams::jwtAuthTokenValidityMinutes)) {
        LOG_ERROR << "Failed to store token in Redis";
        return "";
    }

    return token;
}

bool JwtAuthFilter::storeTokenInRedis(const std::string& token, int validityMinutes) {
    try {
        auto redis_client = drogon::app().getRedisClient();
        auto redis_key = "access_token:" + token;

        LOG_INFO << "Storing token in Redis:\n"
                 << redis_key << "\n"
                 << validityMinutes * 60 << "token" << token << "\n";

        auto result = redis_client->execCommandSync(
            [](const drogon::nosql::RedisResult& r) { return r.asString() == "OK"; }, "SETEX %s %d %s",
            redis_key.c_str(), static_cast<int>(CryptoParams::jwtAuthTokenValidityMinutes * 60), token.c_str());

        return result;
    } catch (const drogon::nosql::RedisException& e) {
        LOG_ERROR << "Failed to store token in Redis: " << e.what();
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR << "Unexpected error while storing token: " << e.what();
        return false;
    }
}

bool JwtAuthFilter::invalidateToken(const std::string& token) {
    if (token.empty())
        return false;

    auto redis_client = drogon::app().getRedisClient();
    std::string redis_key = "access_token:" + token;

    try {
        return redis_client->execCommandSync([](const drogon::nosql::RedisResult& r) { return r.asInteger() > 0; },
                                             "DEL %s", redis_key.c_str());
    } catch (const drogon::nosql::RedisException&) {
        return false;
    }
}

int JwtAuthFilter::getUserIdFromToken(const std::string& token) {
    try {
        auto decoded = jwt::decode<traits>(token);
        auto userId = decoded.get_payload_claim("user_id").as_string();
        return std::stoi(userId);
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to get user ID from token: " << e.what();
        return -1;
    }
}

void JwtAuthFilter::doFilter(const drogon::HttpRequestPtr& req,
                             drogon::FilterCallback&& fcb,
                             drogon::FilterChainCallback&& fccb) {
    // Проверяем, не является ли путь исключением
    const std::string path = req->getPath();
    const std::vector<std::string> excludedPaths = {"/user/signin", "/user/signup", "/user/login/submit",
                                                    "/user/register/submit"};

    if (std::find(excludedPaths.begin(), excludedPaths.end(), path) != excludedPaths.end()) {
        LOG_INFO << "Path is excluded: " << path;
        fccb();
        return;
    }

    auto token = getTokenFromRequest(req);

    if (token.empty()) {
        auto resp = drogon::HttpResponse::newRedirectionResponse("/user/signin");
        resp->setStatusCode(drogon::k302Found);
        fcb(resp);
        return;
    }

    if (!verifyToken(token)) {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k401Unauthorized);
        resp->setBody("Недействительный токен авторизации");
        fcb(resp);
        return;
    }

    auto redis_client = drogon::app().getRedisClient();
    std::string redis_key = "access_token:" + token;

    try {
        auto result = redis_client->execCommandSync(
            [](const drogon::nosql::RedisResult& r) {
                return r.type() != drogon::nosql::RedisResultType::kNil ? r.asString() : "";
            },
            "GET %s", redis_key.c_str());

        if (result.empty()) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k401Unauthorized);
            resp->setBody("Токен не найден в системе");
            fcb(resp);
            return;
        }

        fccb();
    } catch (const drogon::nosql::RedisException& ex) {
        LOG_ERROR << "Redis error while checking token: " << ex.what();
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k500InternalServerError);
        resp->setBody("Ошибка при проверке токена");
        fcb(resp);
    }
}

bool JwtAuthFilter::verifyToken(const std::string& token) {
    try {
        LOG_INFO << "Attempting to verify token";
        auto decoded = jwt::decode<traits>(token);

        auto verifier = jwt::verify<traits>()
                            .with_issuer(CryptoParams::jwtIssuer)
                            .allow_algorithm(jwt::algorithm::hs256{CryptoParams::jwtSecret});

        verifier.verify(decoded);
        LOG_INFO << "Token verified successfully";
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR << "Token verification failed: " << e.what();
        return false;
    }
}

std::string JwtAuthFilter::getTokenFromRequest(const drogon::HttpRequestPtr& req) {
    // Сначала проверяем cookie
    auto cookies = req->cookies();
    auto it = cookies.find("access_token");
    if (it != cookies.end()) {
        std::cout << "Cookie found: " << it->second << "\n";
        return it->second;
    }

    // Затем проверяем заголовок Authorization
    auto auth_header = req->getHeader("Authorization");
    if (!auth_header.empty() && auth_header.find("Bearer ") == 0) {
        return auth_header.substr(7);
    }

    return "";
}