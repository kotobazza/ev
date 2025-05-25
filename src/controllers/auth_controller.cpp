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
#include "crypto_params.hpp"
#include "drogon/HttpResponse.h"
#include "jwt_auth_filter.h"

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

AuthController::AuthController() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

void AuthController::handleSignin(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
    LOG_INFO << "requested Signin page";

    auto resp = HttpResponse::newHttpViewResponse("login");
    resp->setContentTypeCode(ContentType::CT_TEXT_HTML);
    callback(resp);
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
            try {
                if (r.empty()) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k401Unauthorized);
                    resp->setBody("Неверный логин или пароль");
                    callback(resp);
                    return;
                }

                try {
                    auto db_password_hash = r[0]["password_hash"].as<std::string>();
                    auto userId = r[0]["id"].as<int>();

                    // Проверяем пароль
                    if (crypto_pwhash_str_verify(db_password_hash.c_str(), password.c_str(), password.size()) != 0) {
                        auto resp = HttpResponse::newHttpResponse();
                        resp->setStatusCode(k401Unauthorized);
                        resp->setBody("Неверный логин или пароль");
                        callback(resp);
                        return;
                    }

                    auto token = JwtAuthFilter::createToken(userId);
                    if (token.empty()) {
                        auto resp = HttpResponse::newHttpResponse();
                        resp->setStatusCode(k500InternalServerError);
                        resp->setBody(std::string("Error creating token"));
                        callback(resp);
                        return;
                    }

                    LOG_INFO << "Token created: " << token;

                    Cookie cookie("access_token", token);
                    cookie.setPath("/");
                    cookie.setHttpOnly(true);
                    cookie.setMaxAge(CryptoParams::jwtAuthTokenValidityMinutes * 60);

                    auto resp = HttpResponse::newRedirectionResponse("/user/profile");
                    resp->setStatusCode(k302Found);
                    resp->addCookie(cookie);

                    LOG_INFO << "Ready to send redirection response from login";

                    callback(resp);
                    return;
                } catch (const std::exception& e) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody("Ошибка: некорректные данные пользователя");
                    callback(resp);
                    return;
                }
            } catch (const std::exception& e) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setBody(std::string("Внутренняя ошибка сервера: ") + e.what());
                callback(resp);
                return;
            }
        },
        [callback](const orm::DrogonDbException& e) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k500InternalServerError);
            resp->setBody("DB ошибка: " + std::string(e.base().what()));
            callback(resp);
            return;
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

    client->execSqlAsync(
        "SELECT id FROM Users WHERE login=$1",
        [password, login, callback, client](const orm::Result& r) mutable {
            try {
                if (!r.empty()) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k409Conflict);
                    resp->setBody("Ошибка: логин уже занят");
                    callback(resp);
                    return;
                }

                char hashed_password[crypto_pwhash_STRBYTES];
                if (crypto_pwhash_str(hashed_password, password.c_str(), password.size(),
                                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody("Ошибка при хешировании пароля");
                    callback(resp);
                    return;
                }

                client->execSqlAsync(
                    "INSERT INTO Users (login, password_hash) VALUES ($1, $2) RETURNING id",
                    [callback](const orm::Result& r) {
                        try {
                            if (r.empty()) {
                                auto resp = HttpResponse::newHttpResponse();
                                resp->setStatusCode(k500InternalServerError);
                                resp->setBody("Ошибка: не удалось получить ID нового пользователя");
                                callback(resp);
                                return;
                            }

                            try {
                                auto userId = r[0]["id"].as<int>();
                                auto token = JwtAuthFilter::createToken(userId);
                                if (token.empty()) {
                                    auto resp = HttpResponse::newHttpResponse();
                                    resp->setStatusCode(k500InternalServerError);
                                    resp->setBody("Ошибка при создании токена");
                                    callback(resp);
                                    return;
                                }

                                LOG_INFO << "Token created: " << token;

                                auto resp = HttpResponse::newRedirectionResponse("/user/profile");
                                resp->setStatusCode(k302Found);

                                Cookie cookie("access_token", token);
                                cookie.setPath("/");
                                cookie.setHttpOnly(true);
                                cookie.setMaxAge(CryptoParams::jwtAuthTokenValidityMinutes * 60);

                                resp->addCookie(cookie);

                                LOG_INFO << "Ready to send redirection response from signup";

                                callback(resp);
                            } catch (const std::exception& e) {
                                auto resp = HttpResponse::newHttpResponse();
                                resp->setStatusCode(k500InternalServerError);
                                resp->setBody("Ошибка: некорректные данные пользователя");
                                callback(resp);
                            }
                        } catch (const std::exception& e) {
                            auto resp = HttpResponse::newHttpResponse();
                            resp->setStatusCode(k500InternalServerError);
                            resp->setBody(std::string("Внутренняя ошибка сервера: ") + e.what());
                            callback(resp);
                        }
                    },
                    [callback](const orm::DrogonDbException& e) {
                        auto resp = HttpResponse::newHttpResponse();
                        resp->setStatusCode(k500InternalServerError);
                        resp->setBody("DB ошибка при регистрации: " + std::string(e.base().what()));
                        callback(resp);
                    },
                    login, std::string(hashed_password));
            } catch (const std::exception& e) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setBody(std::string("Внутренняя ошибка сервера: ") + e.what());
                callback(resp);
            }
        },
        [callback](const orm::DrogonDbException& e) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k500InternalServerError);
            resp->setBody("DB ошибка при проверке логина: " + std::string(e.base().what()));
            callback(resp);
        },
        login);
}
