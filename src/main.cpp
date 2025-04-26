#include <drogon/drogon.h>

int main() {
    drogon::app()
        .setLogPath("./logs")  // Логи будут сохраняться в папку ./logs
        .setLogLevel(trantor::Logger::kWarn)  // Уровень логирования (только предупреждения)
        .addListener("0.0.0.0", 8080)  // Слушаем на всех интерфейсах, порт 8080
        .setDocumentRoot("../www")  // Папка со статическими файлами (HTML, CSS, JS)
        .enableSession(86400)  // Включаем сессии (таймаут 86400 секунд = 1 день)
        .run();
}