#include <drogon/drogon.h>
#include <drogon/HttpTypes.h>

int main() {
    drogon::app().registerHandler(
        "/main",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setBody("<h1>Главная страница</h1>");
            callback(resp);
        },
        {drogon::Get}
    );

    // Обработчик для /about
    drogon::app().registerHandler(
        "/about",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setBody("<h1>О нас</h1><p>Мы изучаем Drogon!</p>");
            callback(resp);
        },
        {drogon::Get}
    );

    drogon::app().registerHandler(
        "/api/data",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            Json::Value jsonData;
            jsonData["name"] = "Drogon";
            jsonData["version"] = "1.0";
            jsonData["features"] = Json::arrayValue;
            jsonData["features"].append("Fast");
            jsonData["features"].append("Asynchronous");

            auto resp = drogon::HttpResponse::newHttpJsonResponse(jsonData);
            callback(resp);
        },
        {drogon::Get}
    );

    drogon::app().registerHandler(
        "/dynamic",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto now = (double)trantor::Date::now().secondsSinceEpoch();
            
            drogon::HttpViewData data;
            data.insert("title", "Динамическая страница");
            data.insert("header", "Привет, Drogon CSP!");
            data.insert("now", now);

            auto resp = drogon::HttpResponse::newHttpViewResponse("test.csp", data);
            callback(resp);
        },
        {drogon::Get}
    );

    drogon::app()
        .setLogPath("./logs")  // Логи будут сохраняться в папку ./logs
        .setLogLevel(trantor::Logger::kTrace)  // Уровень логирования (только предупреждения)
        .addListener("0.0.0.0", 8080)  // Слушаем на всех интерфейсах, порт 8080
        .setDocumentRoot("../www")  // Папка со статическими файлами (HTML, CSS, JS)
        .enableSession(86400)  // Включаем сессии (таймаут 86400 секунд = 1 день)
        .enableDynamicViewsLoading({"../views"})
        .run();
}