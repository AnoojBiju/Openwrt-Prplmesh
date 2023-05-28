# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

#set default odl folder
set(DATAMODELS_PATH ${CMAKE_CURRENT_BINARY_DIR}/odl)
message(STATUS  "Using CMake version : "  ${CMAKE_VERSION})

# The `configure_file_odl` function pre-processes .odl.in files and saves the result in the build folder.
# It uses a workaround to avoid parsing ${} variables in odl files. It temporarily replaces ${} with $//{} 
# to prevent the `configure_file` operation from processing these variables.
function(configure_file_odl odl_file_input)
    get_filename_component(odl_file_input_tmp ${odl_file_input} NAME)
    string(REGEX REPLACE "\\.[^.]*$" "" barename ${odl_file_input_tmp})
    message(STATUS  "Preprocessing odl file : "  ${DATAMODELS_PATH}/${barename})
    
    # Workaround to avoid parsing ${} variables in odl files:
    # Use `sed` to replace ${} with $//{} before `configure_file` operation.
    execute_process(COMMAND sed -i "s:\\\\$\\{{:\\\\$//\\{{:g" ${odl_file_input})

    configure_file(${odl_file_input} "${DATAMODELS_PATH}/${barename}")

    # After `configure_file` operation, revert the temporary $//{} back to ${}
    # using `sed` to maintain original syntax.
    execute_process(COMMAND sed -i "s:\\\\$//\\{{:\\\\$\\{{:g" "${DATAMODELS_PATH}/${barename}")
endfunction()

#search for all available .odl.in files in the odl folder and parse them
file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/odl/*.odl.in")
foreach(file ${files})
  configure_file_odl(${file})
endforeach()

# Parse prplmesh_definitions.odl file
message(STATUS "Parse prplmesh_definitions.odl file using amxo : ")
execute_process(COMMAND amxo-cg ${DATAMODELS_PATH}/prplmesh_definitions.odl --no-warnings RESULT_VARIABLE DATAMODEL_PARSE_RESULT)

# If parser find errors - generate FATAL_ERROR
if(${DATAMODEL_PARSE_RESULT})
    message(FATAL_ERROR "Failed to parse controller data model!")
endif()

install(DIRECTORY ${DATAMODELS_PATH} DESTINATION config)
file(COPY ${DATAMODELS_PATH} DESTINATION "${CMAKE_MULTIAP_OUTPUT_DIRECTORY}/config/odl")

message(STATUS "Controller data model tested successfully!")
