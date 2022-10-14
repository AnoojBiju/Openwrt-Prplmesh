# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

project(wbapi VERSION ${prplmesh_VERSION})

message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite} for the ${BoldGreen}${TARGET_PLATFORM}${BoldWhite} platform${ColourReset}")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

list(APPEND wbapi_sources ${MODULE_PATH}/ambiorix_connection.cpp)
list(APPEND wbapi_sources ${MODULE_PATH}/ambiorix_connection_factory.cpp)
list(APPEND wbapi_sources ${MODULE_PATH}/ambiorix_client_factory.cpp)
list(APPEND wbapi_sources ${MODULE_PATH}/ambiorix_client_impl.cpp)
list(APPEND wbapi_sources ${MODULE_PATH}/wbapi_utils.cpp)

find_package(amxb REQUIRED)
find_package(amxc REQUIRED)
find_package(amxd REQUIRED)
find_package(amxp REQUIRED)
list(APPEND WBAPI_LIBS amxb amxc amxd amxp)

# Build the library
add_library(${PROJECT_NAME} ${wbapi_sources})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${prplmesh_VERSION} SOVERSION ${prplmesh_VERSION_MAJOR})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-z,defs")

target_link_libraries(${PROJECT_NAME} PRIVATE ${WBAPI_LIBS} elpp bcl tlvf)

# Install
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )

install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

