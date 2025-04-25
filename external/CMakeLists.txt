include(FetchContent)

# === JsonCpp ===
set(JSONCPP_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    jsoncpp
    GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
    GIT_TAG        1.9.5
)

FetchContent_GetProperties(jsoncpp)
if(NOT jsoncpp_POPULATED)
  FetchContent_Populate(jsoncpp)

  execute_process(
    COMMAND ${CMAKE_COMMAND} -S ${jsoncpp_SOURCE_DIR} -B ${jsoncpp_BINARY_DIR}
            -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
            -DBUILD_STATIC_LIBS=ON
            -DBUILD_SHARED_LIBS=OFF
            -DJSONCPP_WITH_TESTS=OFF
            -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF
  )
  execute_process(
    COMMAND ${CMAKE_COMMAND} --build ${jsoncpp_BINARY_DIR} --target install
  )
endif()

# === Drogon ===
FetchContent_Declare(
    drogon
    GIT_REPOSITORY https://github.com/drogonframework/drogon.git
    GIT_TAG        v1.9.10
)
FetchContent_MakeAvailable(drogon)