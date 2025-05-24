#include "auth_controller.hpp"

#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium
#include "drogon/HttpResponse.h"

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

AuthController::AuthController() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

void AuthController::handleSignin(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
    LOG_INFO << "requested Signin page";

    auto cookies = req->cookies();
    auto it = cookies.find("access_token");
    if (it == cookies.end()) {
        // Нет токена — сразу показываем форму входа
        auto resp = HttpResponse::newHttpViewResponse("login");

        resp->setContentTypeCode(ContentType::CT_TEXT_HTML);
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
                auto resp = HttpResponse::newHttpViewResponse("login");
                resp->setContentTypeCode(ContentType::CT_TEXT_HTML);
                callback(resp);
            } else {
                // Токен валиден — делаем редирект на главную страницу (или куда надо)
                auto resp = HttpResponse::newRedirectionResponse("/user/profile");
                callback(resp);
            }
        },
        [callback](const nosql::RedisException& ex) {
            // Ошибка Redis — лучше показать форму входа, но можно логировать
            auto resp = HttpResponse::newHttpViewResponse("login");
            resp->setContentTypeCode(ContentType::CT_TEXT_HTML);
            callback(resp);
        },
        "GET %s", redis_key.c_str());
}

void AuthController::handleSignup(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
    LOG_INFO << "requested Signup page";

    auto resp = HttpResponse::newHttpViewResponse("registration");
    // auto resp = HttpResponse::newFileResponse("signup.html");
    resp->setContentTypeCode(ContentType::CT_TEXT_HTML);
    callback(resp);
}

void AuthController::handleSubmitLogin(const HttpRequestPtr& req,
                                       std::function<void(const HttpResponsePtr&)>&& callback) {
    LOG_INFO << "asked for auth process submit";

    auto login = req->getParameter("login");
    auto password = req->getParameter("password");

    if (login.empty() || password.empty()) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k400BadRequest);
        resp->setBody("Ошибка: логин и пароль обязательны");
        callback(resp);
        return;
    }

    auto client = app().getDbClient();
    client->execSqlAsync(
        "SELECT id, password_hash FROM Users WHERE login=$1",
        [password, login, callback](const orm::Result& r) mutable {
            if (r.empty()) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k401Unauthorized);
                resp->setBody("Неверный логин или пароль");
                callback(resp);
                return;
            }

            auto db_password_hash = r[0]["password_hash"].as<std::string>();

            // Проверяем пароль
            if (crypto_pwhash_str_verify(db_password_hash.c_str(), password.c_str(), password.size()) != 0) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k401Unauthorized);
                resp->setBody("Неверный логин или пароль");
                callback(resp);
                return;
            }

            // Генерируем JWT
            auto now = std::chrono::system_clock::now();
            auto expires = now + std::chrono::hours(24);

            auto token =
                jwt::create<traits>()
                    .set_type("JWT")
                    .set_issuer("ev")
                    .set_payload_claim("user_id", jwt::basic_claim<traits>(std::to_string(r[0]["id"].as<int>())))
                    .set_issued_at(now)
                    .set_expires_at(expires)
                    .sign(jwt::algorithm::hs256{"your_secret_key"});

            auto redis_client = app().getRedisClient();
            redis_client->execCommandAsync(
                [token, callback](const nosql::RedisResult& result) mutable {
                    auto resp = HttpResponse::newHttpResponse();
                    if (result.asString() == "OK") {
                        resp->setStatusCode(k200OK);

                        Cookie cookie("access_token", token);
                        cookie.setPath("/");
                        cookie.setHttpOnly(true);
                        cookie.setSecure(true);
                        cookie.setMaxAge(86400);  // 24 часа
                        resp->addCookie(cookie);

                        auto resp = HttpResponse::newRedirectionResponse("/user/profile");  // или "/"
                        resp->addCookie(cookie);
                        callback(resp);
                    } else {
                        resp->setStatusCode(k500InternalServerError);
                        resp->setBody("Ошибка: Redis вернул неожиданный результат");
                    }
                    callback(resp);
                },
                [callback](const nosql::RedisException& ex) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody(std::string("Redis ошибка: ") + ex.what());
                    callback(resp);
                },
                "SETEX access_token:%s 86400 %s", token.c_str(), token.c_str());
        },
        [callback](const orm::DrogonDbException& e) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k500InternalServerError);
            resp->setBody("DB ошибка: " + std::string(e.base().what()));
            callback(resp);
        },
        login);
}

void AuthController::handleSubmitRegister(const HttpRequestPtr& req,
                                          std::function<void(const HttpResponsePtr&)>&& callback) {
    LOG_INFO << "asked for auth process submit";

    auto login = req->getParameter("login");
    auto password = req->getParameter("password");
    auto password_confirm = req->getParameter("password_confirm");

    if (login.empty() || password.empty() || password_confirm.empty()) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k400BadRequest);
        resp->setBody("Ошибка: все поля обязательны");
        callback(resp);
        return;
    }

    if (password != password_confirm) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k400BadRequest);
        resp->setBody("Ошибка: пароли не совпадают");
        callback(resp);
        return;
    }

    auto client = app().getDbClient();

    // Проверяем, что логин уникален
    client->execSqlAsync(
        "SELECT id FROM Users WHERE login=$1",
        [password, login, callback, client](const orm::Result& r) mutable {
            if (!r.empty()) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k409Conflict);
                resp->setBody("Ошибка: логин уже занят");
                callback(resp);
                return;
            }

            // Хешируем пароль
            char hashed_password[crypto_pwhash_STRBYTES];
            if (crypto_pwhash_str(hashed_password, password.c_str(), password.size(), crypto_pwhash_OPSLIMIT_MODERATE,
                                  crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Ошибка при хешировании пароля");
                callback(resp);
                return;
            }

            // Вставляем пользователя в БД
            client->execSqlAsync(
                "INSERT INTO Users (login, password_hash) VALUES ($1, $2)",
                [callback](const orm::Result&) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k200OK);
                    resp->setBody("Регистрация прошла успешно. <a href=\"/user/signin\">Войти</a>");
                    callback(resp);
                },
                [callback](const orm::DrogonDbException& e) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody("DB ошибка при регистрации: " + std::string(e.base().what()));
                    callback(resp);
                },
                login, std::string(hashed_password));
        },
        [callback](const orm::DrogonDbException& e) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k500InternalServerError);
            resp->setBody("DB ошибка при проверке логина: " + std::string(e.base().what()));
            callback(resp);
        },
        login);
}
