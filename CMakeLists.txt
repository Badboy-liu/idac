cmake_minimum_required(VERSION 4.1)

project(idac
    VERSION 0.1.0
    LANGUAGES CXX
)

find_package(OpenSSL REQUIRED)
find_package(RapidJSON CONFIG REQUIRED)

add_executable(idac
    src/main.cpp
)

target_compile_features(idac PRIVATE cxx_std_23)

if(TARGET RapidJSON::RapidJSON)
    target_link_libraries(idac PRIVATE RapidJSON::RapidJSON)
elseif(TARGET rapidjson)
    target_link_libraries(idac PRIVATE rapidjson)
elseif(TARGET RapidJSON)
    target_link_libraries(idac PRIVATE RapidJSON)
elseif(DEFINED RAPIDJSON_INCLUDE_DIRS)
    target_include_directories(idac SYSTEM PRIVATE ${RAPIDJSON_INCLUDE_DIRS})
elseif(DEFINED RAPIDJSON_INCLUDE_DIR)
    target_include_directories(idac SYSTEM PRIVATE ${RAPIDJSON_INCLUDE_DIR})
elseif(DEFINED RapidJSON_INCLUDE_DIRS)
    target_include_directories(idac SYSTEM PRIVATE ${RapidJSON_INCLUDE_DIRS})
elseif(DEFINED RapidJSON_INCLUDE_DIR)
    target_include_directories(idac SYSTEM PRIVATE ${RapidJSON_INCLUDE_DIR})
else()
    message(FATAL_ERROR "RapidJSON package was found, but no known RapidJSON target or include directory is available")
endif()

target_link_libraries(idac PRIVATE OpenSSL::Crypto)

install(TARGETS idac RUNTIME DESTINATION bin)
install(FILES data/licenses.json DESTINATION share/idac)
