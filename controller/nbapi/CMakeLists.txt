# Set controller data model path
set(DATAMODEL_PATH ${CMAKE_CURRENT_SOURCE_DIR}/odl/controller.odl)

message(STATUS "Test controller data model:")

# Parse controller.odl file
execute_process(COMMAND amxo-cg ${DATAMODEL_PATH} RESULT_VARIABLE DATAMODEL_PARSE_RESULT)

# If parser find errors - generate FATAL_ERROR
if(${DATAMODEL_PARSE_RESULT})
    message(FATAL_ERROR "Failed to parse controller data model!")
endif()

message(STATUS "Controller data model tested successfully!")
