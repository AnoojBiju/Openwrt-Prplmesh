# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

#set default odl folder
set(DATAMODELS_PATH ${CMAKE_CURRENT_BINARY_DIR}/odl)
message(STATUS  "Using CMake version : "  ${CMAKE_VERSION})

# The `configure_file_odl` function preprocesses .odl.in files. 
# It temporarily replaces ${} to avoid its parsing by `configure_file`.
function(configure_file_odl odl_file_input)
    # Extract the directory and filename
    get_filename_component(input_directory ${odl_file_input} DIRECTORY)
    get_filename_component(input_filename ${odl_file_input} NAME)

    # Get the filename without extension
    string(REGEX REPLACE "\\.[^.]*$" "" barename ${input_filename})

    # Get the relative path from the source directory to the input directory
    file(RELATIVE_PATH relative_path ${CMAKE_CURRENT_SOURCE_DIR} ${input_directory})

    # Ensure the output directory exists
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${relative_path}")

    # Replace ${} with $@@{} to prevent parsing by `configure_file`.
    execute_process(COMMAND bash "-c" "sed -r -i 's/\\$\\{([^}]*)\\}/\\$@@\\{\\1\\}/g' ${odl_file_input}")

    message(STATUS  "${BoldCyan}Generating odl file${ColourReset} : " ${barename})
    configure_file(${odl_file_input} "${CMAKE_CURRENT_BINARY_DIR}/${relative_path}/${barename}")

    # Revert $@@{} back to ${} after `configure_file`.
    execute_process(COMMAND bash "-c" "sed -r -i 's/\\$@@\\{([^}]*)\\}/\\$\\{\\1\\}/g' ${CMAKE_CURRENT_BINARY_DIR}/${relative_path}/${barename}")
endfunction()


#search for all available .odl.in files in the odl folder and parse them
file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/odl/*.odl.in")
foreach(file ${files})
  configure_file_odl(${file})
endforeach()

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/odl/defaults.d/*.odl.in")
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
message(STATUS "${BoldGreen}Controller data model tested successfully!${ColourReset}")

install(DIRECTORY ${DATAMODELS_PATH} DESTINATION config)
if(IS_DIRECTORY ${DATAMODELS_PATH}/defaults.d)
    install(DIRECTORY ${DATAMODELS_PATH}/defaults.d DESTINATION config/odl)
endif()
