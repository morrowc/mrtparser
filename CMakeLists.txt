cmake_minimum_required(VERSION 3.10)
project(mrtparser CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Coverage options
option(ENABLE_COVERAGE "Enable coverage reporting" ON)

if(ENABLE_COVERAGE)
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

# Find dependencies
find_package(BZip2 REQUIRED)
find_package(ZLIB REQUIRED)

include(FetchContent)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

include_directories(include)

# Library target for shared code
add_library(mrtparser_lib
    src/mrt_parser.cpp
    src/bgp_parser.cpp
)
target_link_libraries(mrtparser_lib BZip2::BZip2 ZLIB::ZLIB nlohmann_json::nlohmann_json)

# Main executable
add_executable(mrtparser src/main.cpp)
target_link_libraries(mrtparser mrtparser_lib nlohmann_json::nlohmann_json)

# Tests
enable_testing()
find_package(GTest REQUIRED)
add_executable(mrtparser_test tests/mrt_parser_test.cpp)
target_link_libraries(mrtparser_test mrtparser_lib GTest::gtest_main)
add_test(NAME mrt_test COMMAND mrtparser_test)

# Cross-language synchronization test
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME sync_test 
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/check_sync.py
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

if(ENABLE_COVERAGE)
    # Check lcov version for compatibility flags
    execute_process(COMMAND lcov --version OUTPUT_VARIABLE LCOV_VERSION_STR)
    if(LCOV_VERSION_STR MATCHES "version 2")
        set(LCOV_FLAGS "--ignore-errors" "inconsistent,mismatch,gcov,source,graph")
        set(GENHTML_FLAGS "--ignore-errors" "inconsistent,mismatch,source")
    else()
        set(LCOV_FLAGS "--ignore-errors" "mismatch,gcov,source,graph")
        set(GENHTML_FLAGS "--ignore-errors" "mismatch,source")
    endif()

    find_program(GCOV_PATH gcov)
    if(GCOV_PATH)
        set(LCOV_FLAGS ${LCOV_FLAGS} "--gcov-tool" ${GCOV_PATH})
    endif()

    add_custom_target(coverage
        COMMAND lcov ${LCOV_FLAGS} --capture --directory . --output-file coverage.info
        COMMAND lcov ${LCOV_FLAGS} --remove coverage.info '/usr/*' '*/tests/*' --output-file coverage.info
        COMMAND genhtml ${GENHTML_FLAGS} coverage.info --output-directory coverage_report
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating coverage report"
    )
endif()
