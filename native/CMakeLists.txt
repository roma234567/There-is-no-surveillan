cmake_minimum_required(VERSION 3.22)
project(PrivacySentinelNative VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -O2 -fPIC)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(Threads REQUIRED)

# 1. Core epoll daemon: sentineld
add_executable(sentineld
    daemon/sentineld.cpp
)
target_link_libraries(sentineld PRIVATE Threads::Threads)

# 2. Zero-port CLI bridge: sentinelctl
add_executable(sentinelctl
    cli/sentinelctl.cpp
)

# 3. Zygisk Native Module shared library (built when Android NDK / JNI is available)
if(ANDROID)
    find_library(LOG_LIB log)
    add_library(privacy_sentinel_zygisk SHARED
        zygisk/zygisk_module.cpp
    )
    target_link_libraries(privacy_sentinel_zygisk PRIVATE ${LOG_LIB})
    set_target_properties(privacy_sentinel_zygisk PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        LINK_FLAGS "-Wl,--exclude-libs,ALL -Wl,--gc-sections"
    )
endif()
