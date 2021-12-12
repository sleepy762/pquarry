cmake_minimum_required(VERSION 3.10)

# Set the project name
set(PROJECT_NAME "NetScout")
project(${PROJECT_NAME})

# Get all the source files
aux_source_directory("src" coresrc)

# Create the executable
add_executable(${PROJECT_NAME} ${coresrc})

# Specify the C++ Standard and flags
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-O2 -Wall -Wextra -pedantic")
set(CMAKE_EXE_LINKER_FLAGS "-ltins") # Link with libtins

# Include headers
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
