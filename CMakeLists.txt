cmake_minimum_required(VERSION 3.10)
project(mrtparser CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies
find_package(BZip2 REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(include)

# Main executable
add_executable(mrtparser
    src/main.cpp
    src/mrt_parser.cpp
    src/bgp_parser.cpp
)

target_link_libraries(mrtparser
    BZip2::BZip2
    ZLIB::ZLIB
)

# Optional: Add tests if gtest is found
# find_package(GTest)
# if(GTEST_FOUND)
#     enable_testing()
#     add_subdirectory(tests)
# endif()
