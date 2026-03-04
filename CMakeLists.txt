cmake_minimum_required(VERSION 3.20)
project(sysinf VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(sysinf
    src/main.cpp
    src/cli.cpp
    src/util.cpp
    src/output.cpp
    src/collectors.cpp
    src/runtime_status.cpp
)

target_include_directories(sysinf PRIVATE src)

target_link_libraries(sysinf PRIVATE advapi32)

if(MINGW)
    target_link_options(sysinf PRIVATE -static -static-libgcc -static-libstdc++)
endif()

enable_testing()

add_executable(sysinf_tests
    tests/cli_tests.cpp
    src/cli.cpp
    src/output.cpp
    src/util.cpp
)

target_include_directories(sysinf_tests PRIVATE src)
add_test(NAME sysinf_tests COMMAND sysinf_tests)
