cmake_minimum_required(VERSION 3.15)
project(PasswordGuardianPro LANGUAGES CXX)

# Force the modern C++17 language standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tell the compiler to look in the current directory for header (.h) files
include_directories(.)

# Automatically gather all your source (.cpp) files in this folder
file(GLOB SOURCES "*.cpp")

# Define the final executable program output
add_executable(PasswordGuardianPro ${SOURCES})

# Windows-specific: Enable clean warnings during build compilation
if(MSVC)
    target_compile_options(PasswordGuardianPro PRIVATE /W4)
endif()