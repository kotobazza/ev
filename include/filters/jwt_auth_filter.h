#pragma once

#include <drogon/HttpFilter.h>
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>
#include <string>
#include "crypto_params.hpp"

class JwtAuthFilter : public drogon::HttpFilter<JwtAuthFilter> {
   public:
    JwtAuthFilter();
    virtual void doFilter(const drogon::HttpRequestPtr& req,
                          drogon::FilterCallback&& fcb,
                          drogon::FilterChainCallback&& fccb) override;

    // Методы для работы с токеном
    static std::string createToken(int userId);
    static bool invalidateToken(const std::string& token);
    static bool storeTokenInRedis(const std::string& token, int validityMinutes);
    static int getUserIdFromToken(const std::string& token);
    static bool verifyToken(const std::string& token);
    static std::string getTokenFromRequest(const drogon::HttpRequestPtr& req);

   private:
};