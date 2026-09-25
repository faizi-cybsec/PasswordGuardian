cmake_minimum_required(VERSION 3.15)
project(PasswordGuardianPro LANGUAGES CXX)

# Force the modern C++17 language standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Point CMake to your new headers folder
include_directories(include)

# Find all source files inside the src folder
file(GLOB SOURCES "src/*.cpp")

# Define the final executable program output
add_executable(PasswordGuardianPro ${SOURCES})

# Windows-specific: Enable clean warnings during build compilation
if(MSVC)
    target_compile_options(PasswordGuardianPro PRIVATE /W4)
endif()