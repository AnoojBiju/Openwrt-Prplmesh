# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

project(nbapi VERSION ${prplmesh_VERSION})

message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite} for the ${BoldGreen}${TARGET_PLATFORM}${BoldWhite} platform${ColourReset}")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

# Common Sources
if (ENABLE_NBAPI)
    set(nbapi_sources ${MODULE_PATH}/nbapi.cpp )
endif()

set(nbapi_dummy ${MODULE_PATH}/ambiorix_dummy.cpp )

# Include AMBIORIX in the build
if (ENABLE_NBAPI)
    find_package(amxb REQUIRED)
    find_package(amxc REQUIRED)
    find_package(amxd REQUIRED)
    find_package(amxp REQUIRED)
    find_package(amxo REQUIRED)
    list(APPEND NBAPI_LIBS amxb amxc amxd amxp amxo)
endif()

# Build the library
if (ENABLE_NBAPI)
    add_library(${PROJECT_NAME} ${nbapi_sources} ${nbapi_dummy})
else ()
    add_library(${PROJECT_NAME} ${nbapi_dummy})
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${prplmesh_VERSION} SOVERSION ${prplmesh_VERSION_MAJOR})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-z,defs")

if (ENABLE_NBAPI)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${NBAPI_LIBS} mapfcommon elpp)
else ()
    target_link_libraries(${PROJECT_NAME} PRIVATE mapfcommon elpp)
endif()

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
