project(beerocks_fronthaul VERSION ${prplmesh_VERSION})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite} for the ${BoldGreen}${TARGET_PLATFORM}${BoldWhite} platform${ColourReset}")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

file(GLOB fronthaul_manager_sources 
    ${MODULE_PATH}/monitor/*.c*
    ${MODULE_PATH}/ap_manager/*.c*
    ${MODULE_PATH}/*.c*
)

# UGW
if (TARGET_PLATFORM STREQUAL "ugw")

    # UGW ugwhelper library
    add_library(ugwhelper SHARED IMPORTED)
    set_target_properties(ugwhelper PROPERTIES
        IMPORTED_LOCATION "${PLATFORM_STAGING_DIR}/usr/lib/libugwhelper.so"
    )

    # Platform specific libraries
    list(APPEND LIBS ugwhelper)

endif()

if (USE_PRPLMESH_WHM)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_PRPLMESH_WHM")
    list(APPEND LIBS wbapi)
endif()

#FEATURE_PRE_ASSOCIATION_STEERING
list(FIND FEATURES "FEATURE_PRE_ASSOCIATION_STEERING" _feature_pre_association_steering_index)
if(${_feature_pre_association_steering_index} GREATER -1)
    file(GLOB RDKB_SOURCES ${MODULE_PATH}/monitor/pre_association_steering/*.c*)
    list(APPEND fronthaul_manager_sources  ${RDKB_SOURCES})
endif()

add_executable(${PROJECT_NAME} ${fronthaul_manager_sources})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-z,defs")
target_link_libraries(${PROJECT_NAME} bcl btlvf rt dl tlvf elpp bwl mapfcommon bpl ${LIBS})

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
