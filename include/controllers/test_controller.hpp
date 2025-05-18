#pragma once
#include <drogon/HttpController.h>

using namespace drogon;

class TestController : public drogon::HttpController<TestController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(TestController::handleDbTest, "/test/db", Get);
    ADD_METHOD_TO(TestController::handleRedisTest, "/test/redis", Get);
    ADD_METHOD_TO(TestController::handleHello, "/test/hello", Get);
    METHOD_LIST_END

    void handleDbTest(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void handleRedisTest(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
    void handleHello(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback);
};