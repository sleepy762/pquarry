cmake_minimum_required(VERSION 3.10)

# Setting the main project name
set(PROJECT_NAME "NetScout")
project(${PROJECT_NAME})

# Defining the target names
set(CLIENT_NAME ${PROJECT_NAME})
set(SERVER_NAME "${PROJECT_NAME}Server")

# Specifying the C++ Standard and flags
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-O2 -Wall -Wextra -pedantic")
set(CMAKE_EXE_LINKER_FLAGS "-ltins") # Link with libtins


# Getting all the client source files
aux_source_directory("client/src" client_core_src)
# Creating the client executable
add_executable(${CLIENT_NAME} ${client_core_src})
# Including the client headers
target_include_directories(${CLIENT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/client/include
)


# Getting all the server source files
aux_source_directory("server/src" server_core_src)
# Creating the server executable
add_executable(${SERVER_NAME} ${server_core_src})
# Including the server headers
target_include_directories(${SERVER_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/server/include
)
