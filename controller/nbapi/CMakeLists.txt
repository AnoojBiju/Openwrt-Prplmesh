# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

#set default odl folder
set(DATAMODELS_PATH ${CMAKE_CURRENT_BINARY_DIR}/odl)
message(STATUS  "Using CMake version : "  ${CMAKE_VERSION})

# The `configure_file_odl` function preprocesses .odl.in files. It temporarily replaces ${} to avoid its parsing by `configure_file`.
function(configure_file_odl odl_file_input)
    get_filename_component(odl_file_input_tmp ${odl_file_input} NAME)
    string(REGEX REPLACE "\\.[^.]*$" "" barename ${odl_file_input_tmp})
    
    # Replace ${} with $@@{} to prevent parsing by `configure_file`.
    execute_process(COMMAND bash "-c" "sed -r -i 's/\\$\\{([^}]*)\\}/\\$@@\\{\\1\\}/g' ${odl_file_input}")
    
    message(STATUS  "${BoldCyan}Generating odl file${ColourReset} : " ${barename})
    configure_file(${odl_file_input} "${DATAMODELS_PATH}/${barename}")

    # Revert $@@{} back to ${} after `configure_file`.
    execute_process(COMMAND bash "-c" "sed -r -i 's/\\$@@\\{([^}]*)\\}/\\$\\{\\1\\}/g' ${DATAMODELS_PATH}/${barename}")
endfunction()

#search for all available .odl.in files in the odl folder and parse them
file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/odl/*.odl.in")
foreach(file ${files})
  configure_file_odl(${file})
endforeach()

# Parse prplmesh_definitions.odl file
message(STATUS "${BoldYellow}Parse odl using amxo${ColourReset} : prplmesh.odl")
execute_process(COMMAND amxo-cg ${DATAMODELS_PATH}/prplmesh.odl --no-warnings RESULT_VARIABLE DATAMODEL_PARSE_RESULT)

# If parser find errors - generate FATAL_ERROR
if(${DATAMODEL_PARSE_RESULT})
    message(FATAL_ERROR "Failed to parse controller data model!")
endif()

install(DIRECTORY ${DATAMODELS_PATH} DESTINATION config)
file(COPY ${DATAMODELS_PATH} DESTINATION "${CMAKE_MULTIAP_OUTPUT_DIRECTORY}/config/odl")

message(STATUS "${BoldGreen}Controller data model tested successfully!${ColourReset}")
