#include "test_controller.hpp"

#include <drogon/HttpResponse.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>


using namespace drogon;
using namespace drogon::orm;

void TestController::handleDbTest(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback)
{
    LOG_INFO << "asked for dbtest page";
    auto client = app().getDbClient("default");
    if (!client)
    {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k500InternalServerError);
        resp->setBody("DB client 'default' not found or not configured");
        callback(resp);
        return;
    }

    client->execSqlAsync("SELECT NOW()", [callback](const Result &r) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setBody("PostgreSQL response: " + r[0]["now"].as<std::string>());
        callback(resp);
    },
    [callback](const DrogonDbException &e) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k500InternalServerError);
        resp->setBody("DB error: " + std::string(e.base().what()));
        callback(resp);
    });
}

void TestController::handleRedisTest(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback)
{
    LOG_INFO << "asked for redistest page";
    auto redis = app().getRedisClient("default");

    redis->execCommandAsync(
        [callback](const nosql::RedisResult &result) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setBody("Redis PING response: " + result.asString());
            callback(resp);
        },
        [callback](const std::exception &e) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k500InternalServerError);
            resp->setBody("Redis error: " + std::string(e.what()));
            callback(resp);
        },
        "PING"
    );
}


void TestController::handleHello(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback)
{
    LOG_INFO << "asked for hello page";
    auto resp = HttpResponse::newHttpResponse();
    resp->setBody("Hello from TestController");
    callback(resp);
}