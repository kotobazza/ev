#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium
#include "bigint.hpp"
#include "zkp.hpp"

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

class RegistrarController : public drogon::HttpController<RegistrarController> {
   public:
    METHOD_LIST_BEGIN
    // Изменяем метод на Post и путь на более подходящий
    ADD_METHOD_TO(RegistrarController::submitVote, "/voting/submit", Post);
    ADD_METHOD_TO(RegistrarController::simpleResponse, "/voting/hello", Get);
    METHOD_LIST_END

    RegistrarController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void simpleResponse(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        auto resp = HttpResponse::newFileResponse("../www/yay.html");
        resp->setContentTypeCode(ContentType::CT_TEXT_HTML);
        callback(resp);
    }

    void submitVote(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        LOG_INFO << "got something1\n";
        // Проверяем JWT токен из куков
        auto cookies = req->cookies();
        auto it = cookies.find("access_token");
        if (it == cookies.end()) {
            auto resp = HttpResponse::newRedirectionResponse("/user/signin");
            callback(resp);
            return;
        }
        LOG_INFO << "got something2\n";
        std::string token = it->second;

        // Проверяем токен в Redis
        auto redis_client = app().getRedisClient();
        std::string redis_key = "access_token:" + token;

        redis_client->execCommandAsync(
            [req, callback](const nosql::RedisResult& result) mutable {
                if (result.isNil() || result.asString().empty()) {
                    auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                    callback(resp);
                    return;
                }
                LOG_INFO << "got something3\n";

                // Парсим JSON из тела запроса
                Json::Value jsonData;
                std::string err;
                Json::CharReaderBuilder readerBuilder;
                const std::string jsonStr(req->getBody());
                std::istringstream iss(jsonStr);

                LOG_INFO << "got something4\n";
                if (!Json::parseFromStream(readerBuilder, iss, &jsonData, &err)) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k400BadRequest);
                    resp->setBody("Invalid JSON: " + err);
                    callback(resp);
                    return;
                }
                LOG_INFO << "got something5\n";

                // Извлекаем данные из JSON
                try {
                    std::string votingId = jsonData["voting_id"].asString();
                    std::string encryptedBallot = jsonData["encrypted_ballot"].asString();
                    Json::Value zkpProofE = jsonData["zkp_proof_e_vec"];
                    Json::Value zkpProofZ = jsonData["zkp_proof_z_vec"];
                    Json::Value zkpProofA = jsonData["zkp_proof_a_vec"];

                    std::vector<BigInt> eVec, aVec, zVec;

                    // Выводим полученные данные (в реальном приложении здесь будет обработка)
                    std::cout << "Received vote data:" << std::endl;
                    std::cout << "Voting ID: " << votingId << std::endl;
                    std::cout << "Encrypted ballot: " << encryptedBallot << std::endl;

                    std::cout << "ZKP Proof E:" << std::endl;
                    for (const auto& num : zkpProofE) {
                        std::cout << num.asString() << std::endl;
                        eVec.push_back(BigInt::fromBase64(num.asString()));
                    }

                    std::cout << "ZKP Proof Z:" << std::endl;
                    for (const auto& num : zkpProofZ) {
                        std::cout << num.asString() << std::endl;
                        zVec.push_back(BigInt::fromBase64(num.asString()));
                    }

                    std::cout << "ZKP Proof A:" << std::endl;
                    for (const auto& num : zkpProofA) {
                        std::cout << num.asString() << std::endl;
                        aVec.push_back(BigInt::fromBase64(num.asString()));
                    }

                    BigInt n = BigInt::fromString(
                        "3808960098930485608648231881072338589639824039968925156773850102143996807467302518563771838677"
                        "3707987978862422676776001504944327321619767842592695585112395168004591043832521018334144652551"
                        "9732616495389941656774999338209121700543549400831719887789241885970910418134252817104741423771"
                        "9368219961296017536664110898030773045759691670785960834777405666063211275781635702181066323353"
                        "2786700823093142131312966893811779468000268206241471259761003324378441289093207899532564524460"
                        "6435382024291250728659671413145512628686462515210549163171304955265949603139631964298586781973"
                        "9101552304969141472369610356786341585276597165560904678153777318350320740710061411169870970285"
                        "8349482192882021430063343748979457570607514318162730455178913056329323787430103514045390151591"
                        "1666764017759952412498688048101576360142912015293898206382436361335392251331363553118844131089"
                        "9122538291679559678457087915735890352758023650272235038112237944953061406573442106145741888809"
                        "7070567601139775603343533344881570727473750621141306666639412397985123660455515065530656649359"
                        "0146827567955742287304148357701901434302987420539458031725890644164878569005497703514748900154"
                        "1460437192841504074323578110000830029934258704211681936207762622919306759388206295653058823691"
                        "05698657203");

                    std::vector<BigInt> msgVariants;
                    for (size_t i = 0; i < eVec.size(); i++) {
                        msgVariants.push_back(BigInt(2).pow(BigInt(30 * i)));
                    }

                    CorrectMessageProof scheme(eVec, zVec, aVec, BigInt::fromBase64(encryptedBallot), msgVariants, n);

                    if (scheme.verify()) {
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(true));
                        LOG_INFO << "verified\n";
                        callback(resp);
                    } else {
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(false));
                        resp->setStatusCode(HttpStatusCode::k409Conflict);
                        LOG_INFO << "not verified\n";
                        callback(resp);
                    }

                } catch (const std::exception& e) {
                    LOG_INFO << "got something7\n";
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k400BadRequest);
                    resp->setBody(std::string("Missing or invalid fields: ") + e.what());
                    callback(resp);
                }
            },
            [callback](const nosql::RedisException& ex) {
                auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                callback(resp);
            },
            "GET %s", redis_key.c_str());
    }
};