#pragma once
#include <drogon/HttpController.h>

using namespace drogon;

class AuthController : public drogon::HttpController<AuthController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AuthController::handleSignin, "/user/signin", Get);
    ADD_METHOD_TO(AuthController::handleSubmitLogin, "/user/login/submit", Post);
    ADD_METHOD_TO(AuthController::handleSubmitRegister, "/user/register/submit", Post);
    ADD_METHOD_TO(AuthController::handleSignup, "/user/signup", Get);
    METHOD_LIST_END

    void handleSignin(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void handleSignup(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void handleSubmitLogin(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void handleSubmitRegister(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    
};