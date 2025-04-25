cmake_minimum_required(VERSION 3.16)
project(drogon_app LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Сюда установится jsoncpp
set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/_install" CACHE PATH "" FORCE)

# Добавим путь для поиска drogon зависимостей
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_INSTALL_PREFIX}")

add_subdirectory(external)

# Добавь здесь свои исходники, если нужно
add_executable(drogon_test src/main.cpp)
target_link_libraries(drogon_test PRIVATE drogon)