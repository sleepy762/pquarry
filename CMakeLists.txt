cmake_minimum_required(VERSION 3.10)

# Setting the main project name
set(PROJECT_NAME "pquarry")
project(${PROJECT_NAME})

# Defining the target names
set(CLIENT_NAME ${PROJECT_NAME})
set(SERVER_NAME "${PROJECT_NAME}server")
set(COMMON_PKG_NAME "pqcommon")

# Specifying the C++ Standard and flags
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-O2 -Wall -Wextra -pedantic")
set(CMAKE_EXE_LINKER_FLAGS "-ltins -lcap -lssl -lcrypto") # Link with libtins, libcap and openssl

# Define permissions for the executables
set(PROGRAM_PERMISSIONS
    OWNER_WRITE OWNER_READ OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE
    SETUID)

find_package(OpenSSL REQUIRED)

# Code that both the client and server use compiled into a static lib
aux_source_directory("common/src" common_src)
add_library(${COMMON_PKG_NAME} STATIC ${common_src})
target_include_directories(${COMMON_PKG_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/common/include
)

# Getting all the client source files
aux_source_directory("client/src" client_core_src)
# Creating the client executable
add_executable(${CLIENT_NAME} ${client_core_src})
# Including the client headers
target_include_directories(${CLIENT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/client/include
    ${CMAKE_CURRENT_SOURCE_DIR}/common/include
)
target_link_libraries(${CLIENT_NAME} ${COMMON_PKG_NAME})
add_dependencies(${CLIENT_NAME} ${COMMON_PKG_NAME})


# Getting all the server source files
aux_source_directory("server/src" server_core_src)
# Creating the server executable
add_executable(${SERVER_NAME} ${server_core_src})
# Including the server headers
target_include_directories(${SERVER_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/server/include
    ${CMAKE_CURRENT_SOURCE_DIR}/common/include
)
target_link_libraries(${SERVER_NAME} ${COMMON_PKG_NAME})
add_dependencies(${SERVER_NAME} ${COMMON_PKG_NAME})

# make uninstall
add_custom_target("uninstall" COMMENT "Uninstall installed files")
add_custom_command(
    TARGET "uninstall"
    POST_BUILD
    COMMENT "Uninstall files with install_manifest.txt"
    COMMAND xargs rm -vf < install_manifest.txt || echo Nothing in
            install_manifest.txt to be uninstalled!
)

install(TARGETS ${CLIENT_NAME} ${SERVER_NAME} PERMISSIONS ${PROGRAM_PERMISSIONS})
