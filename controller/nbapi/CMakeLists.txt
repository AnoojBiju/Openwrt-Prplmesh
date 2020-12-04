# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

project(nbapi_actions_controller VERSION ${prplmesh_VERSION})

# Set controller data model path
set(DATAMODELS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/odl)

message(STATUS "Test controller data model:")

# Parse controller.odl file
execute_process(COMMAND amxo-cg ${DATAMODELS_PATH}/controller.odl RESULT_VARIABLE DATAMODEL_PARSE_RESULT)

# If parser find errors - generate FATAL_ERROR
if(${DATAMODEL_PARSE_RESULT})
    message(FATAL_ERROR "Failed to parse controller data model!")
endif()

install(DIRECTORY ${DATAMODELS_PATH} DESTINATION config)
file(COPY ${DATAMODELS_PATH} DESTINATION "${CMAKE_MULTIAP_OUTPUT_DIRECTORY}/config/odl")

message(STATUS "Controller data model tested successfully!")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

# Common Sources
set(nbapi_action_sources ${MODULE_PATH}/on_action.cpp)

# Include AMBIORIX in the build
if (ENABLE_NBAPI)
    find_package(amxc REQUIRED)
    find_package(amxd REQUIRED)
    list(APPEND NBAPI_LIBS amxc amxd)
endif()

set(linked_libs elpp nbapi bcl mapfcommon ${NBAPI_LIBS})


# Build the Controller Data Model Actions library
add_library(${PROJECT_NAME} ${nbapi_action_sources})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${prplmesh_VERSION} SOVERSION ${prplmesh_VERSION_MAJOR})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-z,defs")

target_link_libraries(${PROJECT_NAME} PRIVATE ${linked_libs})

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
