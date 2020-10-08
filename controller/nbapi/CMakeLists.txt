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
