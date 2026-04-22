cmake_minimum_required(VERSION 4.1)
project(idac)

set(CMAKE_CXX_STANDARD 23)
find_package(RapidJSON CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS multiprecision)
find_package(OpenSSL REQUIRED)

add_executable(idac src/main.cpp)
target_link_libraries(idac PRIVATE RapidJSON rapidjson Boost::multiprecision OpenSSL::SSL OpenSSL::Crypto)

