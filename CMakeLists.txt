cmake_minimum_required(VERSION 3.20)
project(kvault VERSION 1.0.0 DESCRIPTION "Linux kernel-assisted encrypted file vault" LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "KernelVault supports Linux only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic -Werror -Wshadow -Wnon-virtual-dtor
        -Wcast-align -Wunused -Woverloaded-virtual -Wconversion
        -Wsign-conversion -Wnull-dereference -Wdouble-promotion -Wformat=2
    )
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # Prevent GCC 12/13/14 known optimizer false-positive in libstdc++ inlined headers
    add_compile_options(-Wno-error=null-dereference)
endif()

option(ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ENABLE_ASAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

add_library(kvault_core STATIC
    src/UniqueFd.cpp
    src/FileLock.cpp
    src/AtomicFileWriter.cpp
    src/KeyDerivation.cpp
    src/VaultManager.cpp
)
target_include_directories(kvault_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_executable(kvault src/main.cpp)
target_link_libraries(kvault PRIVATE kvault_core)

option(BUILD_GUI "Build the optional native Qt desktop interface" OFF)
if(BUILD_GUI)
    find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)
    add_executable(kvault-gui src/gui_main.cpp)
    target_link_libraries(kvault-gui PRIVATE kvault_core Qt6::Widgets)
    install(TARGETS kvault-gui RUNTIME DESTINATION bin)
endif()

find_program(MAKE_EXE make REQUIRED)
add_custom_target(driver
    COMMAND "${MAKE_EXE}" -C "${CMAKE_CURRENT_SOURCE_DIR}/driver" all
    COMMENT "Building the Linux kernel module against the selected kernel headers"
    VERBATIM
)
add_custom_target(driver-clean
    COMMAND "${MAKE_EXE}" -C "${CMAKE_CURRENT_SOURCE_DIR}/driver" clean
    COMMENT "Cleaning Linux kernel module build artifacts"
    VERBATIM
)

find_program(CPPCHECK_EXE cppcheck)
if(CPPCHECK_EXE)
    add_custom_target(cppcheck
        COMMAND "${CPPCHECK_EXE}" --enable=warning,style,performance,portability
            --suppress=missingIncludeSystem --error-exitcode=1 --std=c++20
            -I "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src"
        COMMENT "Running cppcheck on the C++ application"
        VERBATIM
    )
endif()

find_program(CLANG_TIDY_EXE clang-tidy)
if(CLANG_TIDY_EXE)
    add_custom_target(clang-tidy
        COMMAND "${CLANG_TIDY_EXE}" -p "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
        COMMENT "Running clang-tidy on the C++ application"
        VERBATIM
    )
endif()

install(TARGETS kvault RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include/kvault FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(FILES packaging/kvault.desktop DESTINATION share/applications)
install(FILES packaging/icons/kvault.svg DESTINATION share/icons/hicolor/scalable/apps)
install(FILES packaging/udev/99-kvault.rules DESTINATION lib/udev/rules.d)
install(DIRECTORY docs/ DESTINATION share/doc/kvault FILES_MATCHING PATTERN "*.md")

# CPack Packaging Configuration
set(CPACK_PACKAGE_NAME "kvault")
set(CPACK_PACKAGE_VENDOR "KernelVault Team")
set(CPACK_PACKAGE_CONTACT "Sky Ruler <skyruler3281@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Linux kernel-assisted high-assurance encrypted file vault")
set(CPACK_PACKAGE_VERSION "3.0.0")
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.34), libstdc++6 (>= 12)")
include(CPack)

option(BUILD_TESTING "Build the C++ test suite" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
