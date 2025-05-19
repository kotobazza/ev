#include <drogon/Cookie.h>
#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/orm/Result.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <sodium.h>  // libsodium

using namespace drogon;
using traits = jwt::traits::open_source_parsers_jsoncpp;

class VotingController : public drogon::HttpController<VotingController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(VotingController::votingPage, "/votings/{1}", Get);
    METHOD_LIST_END

    VotingController() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    void votingPage(const HttpRequestPtr& req,
                    std::function<void(const HttpResponsePtr&)>&& callback,
                    std::string voting_id) {
        // Сначала пытаемся получить cookie с токеном
        auto cookies = req->cookies();
        auto it = cookies.find("access_token");
        if (it == cookies.end()) {
            // Нет токена — сразу показываем форму входа
            auto resp = HttpResponse::newRedirectionResponse("/user/signin");
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
                    auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                    callback(resp);
                } else {
                    
                    
                    std::vector<std::string> options {"1", "2", "3"};
                    HttpViewData data;


                    data.insert("login", std::string("alice"));
                    data.insert("voting_title", std::string("Voting"));
                    data.insert("voting_question", std::string("Voting?"));
                    data.insert("options", options);  // std::vector<std::string>
                    data.insert("voting_id", std::string("123"));
                    data.insert("crypto_parametr_n", std::string("380896009893048560864823188107233858963982403996892515677385010214399680746730251856377183867737079879788624226767760015049443273216197678425926955851123951680045910438325210183341446525519732616495389941656774999338209121700543549400831719887789241885970910418134252817104741423771936821996129601753666411089803077304575969167078596083477740566606321127578163570218106632335327867008230931421313129668938117794680002682062414712597610033243784412890932078995325645244606435382024291250728659671413145512628686462515210549163171304955265949603139631964298586781973910155230496914147236961035678634158527659716556090467815377731835032074071006141116987097028583494821928820214300633437489794575706075143181627304551789130563293237874301035140453901515911666764017759952412498688048101576360142912015293898206382436361335392251331363553118844131089912253829167955967845708791573589035275802365027223503811223794495306140657344210614574188880970705676011397756033435333448815707274737506211413066666394123979851236604555150655306566493590146827567955742287304148357701901434302987420539458031725890644164878569005497703514748900154146043719284150407432357811000083002993425870421168193620776262291930675938820629565305882369105698657203"));
                    data.insert("options_amount", static_cast<int>(options.size()));
                    auto resp = drogon::HttpResponse::newHttpViewResponse("voting.csp", data);
                    callback(resp);
                }
            },
            [callback](const nosql::RedisException& ex) {
                // Ошибка Redis — лучше показать форму входа, но можно логировать
                auto resp = HttpResponse::newRedirectionResponse("/user/signin");
                callback(resp);
            },
            "GET %s", redis_key.c_str());
    }
};
