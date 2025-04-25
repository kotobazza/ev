#include <drogon/drogon.h>

int main() {
    // Устанавливаем обработчик для корневого пути "/"
    drogon::app().registerHandler(
        "/",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setBody("Привет, это Drogon!");
            callback(resp);
        },
        {drogon::Get});

    // Запускаем сервер на 127.0.0.1:8080
    drogon::app()
        .setLogPath("./logs")  // Опционально: логи в папке logs
        .addListener("127.0.0.1", 8080)
        .setThreadNum(4)       // Опционально: количество потоков
        .run();

    return 0;
}