cmake_minimum_required(VERSION 3.13)

project(nfbridge
    VERSION 0.0.2
    DESCRIPTION "Thin NFQUEUE packet interceptor that delegates verdicts to a Java process"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(NFBRIDGE_WERROR "Treat compiler warnings as errors" OFF)
option(NFBRIDGE_BUILD_TOOLS "Build the mock Java-side responder" ON)

include(GNUInstallDirs)
include(CTest)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQ REQUIRED IMPORTED_TARGET libnetfilter_queue)

set(NFBRIDGE_WARNINGS -Wall -Wextra -Wshadow -Wformat=2 -Wstrict-prototypes
    -Wmissing-prototypes -Wconversion -Wno-sign-conversion)
if(NFBRIDGE_WERROR)
    list(APPEND NFBRIDGE_WARNINGS -Werror)
endif()

# Core library: protocol + IPC + logging. Independent of libnetfilter_queue so it
# can be unit-tested and reused by tools.
add_library(nfbridge_core STATIC
    src/log.c
    src/protocol.c
    src/ipc.c)
target_include_directories(nfbridge_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(nfbridge_core PRIVATE ${NFBRIDGE_WARNINGS})

add_executable(nfbridge
    src/main.c
    src/config.c
    src/nfq.c)
target_compile_definitions(nfbridge PRIVATE NFBRIDGE_VERSION="${PROJECT_VERSION}")
target_compile_options(nfbridge PRIVATE ${NFBRIDGE_WARNINGS})
target_link_libraries(nfbridge PRIVATE nfbridge_core PkgConfig::NFQ)

install(TARGETS nfbridge RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

if(NFBRIDGE_BUILD_TOOLS)
    add_executable(nfbridge-mock-responder tools/mock_responder.c)
    target_compile_options(nfbridge-mock-responder PRIVATE ${NFBRIDGE_WARNINGS})
    target_link_libraries(nfbridge-mock-responder PRIVATE nfbridge_core)
endif()

if(BUILD_TESTING)
    add_executable(test_protocol tests/test_protocol.c)
    target_link_libraries(test_protocol PRIVATE nfbridge_core)
    add_test(NAME protocol COMMAND test_protocol)

    add_executable(test_ipc tests/test_ipc.c)
    target_link_libraries(test_ipc PRIVATE nfbridge_core)
    add_test(NAME ipc COMMAND test_ipc)
endif()
