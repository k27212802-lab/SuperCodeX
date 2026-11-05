cmake_minimum_required(VERSION 3.16)
project(SuperCodeXNativeEngine VERSION 9.281.492 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /O2 /permissive- /utf-8)
else()
    add_compile_options(-Wall -Wextra -O3)
endif()

add_executable(supercodex_cli supercodex_cli.cpp)

set_target_properties(supercodex_cli PROPERTIES
    OUTPUT_NAME "supercodex"
    PROJECT_LABEL "SuperCodeX Native CLI & Decompiler Engine"
)
