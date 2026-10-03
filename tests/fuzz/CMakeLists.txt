cmake_minimum_required(VERSION 3.20)

# Fuzzing Executables
add_executable(fuzz_vault_header fuzz_vault_header.cpp)
target_include_directories(fuzz_vault_header PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(fuzz_vault_header PRIVATE kvault_core)

add_executable(fuzz_directory_archive fuzz_directory_archive.cpp)
target_include_directories(fuzz_directory_archive PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(fuzz_directory_archive PRIVATE kvault_core)

# Register as regression tests in CTest
add_test(NAME FuzzTest.VaultHeader COMMAND fuzz_vault_header)
add_test(NAME FuzzTest.DirectoryArchive COMMAND fuzz_directory_archive)
