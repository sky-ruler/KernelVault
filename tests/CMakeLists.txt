cmake_minimum_required(VERSION 3.20)

include(FetchContent)

# Locate system GTest or fetch release
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    message(STATUS "Google Test not found on system. Fetching via FetchContent...")
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    # Prevent installing GoogleTest artifacts system-wide
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

enable_testing()
include(GoogleTest)

# Combined Test Suite Executable
add_executable(kvault_tests
    test_unique_fd.cpp
    test_file_lock.cpp
    test_atomic_write.cpp
    test_vault_integration.cpp
)

target_include_directories(kvault_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(kvault_tests PRIVATE
    kvault_core
    GTest::gtest
    GTest::gtest_main
)

gtest_discover_tests(kvault_tests)

# Individual test targets for granular debugging
macro(add_individual_test name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(${name} PRIVATE kvault_core GTest::gtest GTest::gtest_main)
endmacro()

add_individual_test(test_unique_fd test_unique_fd.cpp)
add_individual_test(test_file_lock test_file_lock.cpp)
add_individual_test(test_atomic_write test_atomic_write.cpp)
add_individual_test(test_vault_integration test_vault_integration.cpp)

add_subdirectory(fuzz)
