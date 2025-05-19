#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium
#include "zkp.hpp"
#include "bignum.hpp"

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

                    std::vector<BigNum> eVec, aVec, zVec;

                    // Выводим полученные данные (в реальном приложении здесь будет обработка)
                    std::cout << "Received vote data:" << std::endl;
                    std::cout << "Voting ID: " << votingId << std::endl;
                    std::cout << "Encrypted ballot: " << encryptedBallot << std::endl;
                    


                    std::cout << "ZKP Proof E:" << std::endl;
                    for (const auto& num : zkpProofE) {
                        std::cout << num.asString() << std::endl;
                        eVec.push_back(BigNum(num.asString()));
                    }

                    LOG_INFO << "ZPK Proof E size: "<< eVec.size();

                    std::cout << "ZKP Proof Z:" << std::endl;
                    for (const auto& num : zkpProofZ) {
                        std::cout << num.asString() << std::endl;
                        zVec.push_back(BigNum(num.asString()));
                    }

                    std::cout << "ZKP Proof A:" << std::endl;
                    for (const auto& num : zkpProofA) {
                        std::cout << num.asString() << std::endl;
                        aVec.push_back(BigNum(num.asString()));
                    }

                    BigNum n("380896009893048560864823188107233858963982403996892515677385010214399680746730251856377183867737079879788624226767760015049443273216197678425926955851123951680045910438325210183341446525519732616495389941656774999338209121700543549400831719887789241885970910418134252817104741423771936821996129601753666411089803077304575969167078596083477740566606321127578163570218106632335327867008230931421313129668938117794680002682062414712597610033243784412890932078995325645244606435382024291250728659671413145512628686462515210549163171304955265949603139631964298586781973910155230496914147236961035678634158527659716556090467815377731835032074071006141116987097028583494821928820214300633437489794575706075143181627304551789130563293237874301035140453901515911666764017759952412498688048101576360142912015293898206382436361335392251331363553118844131089912253829167955967845708791573589035275802365027223503811223794495306140657344210614574188880970705676011397756033435333448815707274737506211413066666394123979851236604555150655306566493590146827567955742287304148357701901434302987420539458031725890644164878569005497703514748900154146043719284150407432357811000083002993425870421168193620776262291930675938820629565305882369105698657203");
                    
                    
                    std::vector<BigNum> msgVariants;
                    for(size_t i = 0; i< eVec.size(); i++){
                        msgVariants.push_back(BigNum(2).pow(BigNum(30*i)));
                    }

                    

                    CorrectMessageProof scheme(eVec, zVec, aVec, BigNum(encryptedBallot), msgVariants, n);

                    if(scheme.verify()){
                        auto resp = HttpResponse::newHttpJsonResponse(Json::Value(true));
                        LOG_INFO << "verified\n";
                        callback(resp);
                    }
                    else{
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