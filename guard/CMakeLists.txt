cmake_minimum_required(VERSION 3.16)
project(bsecured_guard VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# On macOS, OpenSSL is keg-only under Homebrew; point CMake at it unless told otherwise.
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS /opt/homebrew/opt/openssl@3)
    set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
endif()

# Compile-time configuration. The bSecured CLI passes these per build with
# -D on the configure line; the defaults below only make a standalone build work.
set(BSEC_SERVER_HOST  "127.0.0.1"              CACHE STRING "Host for the TLS pin check")
set(BSEC_SERVER_PORT  "8443"                   CACHE STRING "Port for the TLS pin check")
set(BSEC_REPORT_URL   "https://127.0.0.1:8443" CACHE STRING "Server base URL for reports")
set(BSEC_PINNED_SPKI  ""                        CACHE STRING "base64 SHA-256 of the server SPKI")
set(BSEC_DEVICE_ID    "dev-unconfigured"       CACHE STRING "This build's device id")
set(BSEC_BUILD_ID     "bsec-unconfigured"      CACHE STRING "This build's id")
set(BSEC_SEED_B64     ""                        CACHE STRING "base64 32-byte Ed25519 seed")
set(BSEC_CA_FILE      ""                        CACHE STRING "CA bundle, or empty for the system store")
set(BSEC_POLL_SECONDS "5"                       CACHE STRING "Seconds between checks")
configure_file(include/bsecured_config.h.in "${CMAKE_CURRENT_BINARY_DIR}/bsecured_config.h" @ONLY)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_library(bsecured_guard STATIC src/guard.cpp src/detect.cpp)
target_include_directories(bsecured_guard
    PUBLIC include
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(bsecured_guard
    PUBLIC Threads::Threads
    PRIVATE OpenSSL::SSL OpenSSL::Crypto CURL::libcurl PkgConfig::SODIUM)
target_compile_options(bsecured_guard PRIVATE -Wall -Wextra)

# Standalone tool: one observation, printed.
add_executable(bsecured_probe tools/bsecured_probe.cpp)
target_include_directories(bsecured_probe PRIVATE src)
target_link_libraries(bsecured_probe PRIVATE bsecured_guard OpenSSL::SSL OpenSSL::Crypto CURL::libcurl PkgConfig::SODIUM)
target_compile_options(bsecured_probe PRIVATE -Wall -Wextra)
