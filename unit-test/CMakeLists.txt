cmake_minimum_required(VERSION 3.10)

project(bbn_unit_tests)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add compile options
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks  # 添加 mocks 目录
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../bitcoin_app_base/src
    #${CMAKE_CURRENT_SOURCE_DIR}/../bitcoin_app_base/src
    #${CMAKE_CURRENT_SOURCE_DIR}/../bitcoin_app_base/src/common
    #${CMAKE_CURRENT_SOURCE_DIR}/../bitcoin_app_base/src/crypto
    #${CMAKE_CURRENT_SOURCE_DIR}/../bitcoin_app_base/src/handler
)

# Define source files to test
set(BBN_SOURCES
    ../src/bbn_script.c
    ../src/bbn_data.c
    ../src/bbn_address.c
    ../src/bbn_pub.c
    ../src/bbn_tlv.c
)

# Mock sources
set(MOCK_SOURCES
    mocks/cx.c
    mocks/mock_crypto.c
    mocks/mock_bip32.c
    mocks/mock_printf.c
)

# Test sources
set(TEST_SOURCES
    test_bbn_script.c
    test_bbn_address.c
    test_main.c
)

# Create test executable
add_executable(bbn_tests 
    ${TEST_SOURCES}
    ${MOCK_SOURCES}
    ${BBN_SOURCES}
)

# Link libraries if needed
target_link_libraries(bbn_tests m)

# Enable testing
enable_testing()

# Add test
add_test(NAME bbn_unit_tests COMMAND bbn_tests)

# Coverage support
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
if(ENABLE_COVERAGE)
    target_compile_options(bbn_tests PRIVATE --coverage)
    target_link_options(bbn_tests PRIVATE --coverage)
endif()