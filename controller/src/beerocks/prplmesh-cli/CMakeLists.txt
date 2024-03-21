project(prplmesh_cli VERSION ${prplmesh_VERSION})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite} for the ${BoldGreen}${TARGET_PLATFORM}${BoldWhite} platform${ColourReset}")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

set(cli_libraries bcl btlvf bml mapfcommon)

file(GLOB prplmesh_cli_sources ${MODULE_PATH}/*.cpp)

add_executable(${PROJECT_NAME} ${prplmesh_cli_sources})

# Include AMBIORIX in the build
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DENABLE_NBAPI ${UBUS_SOCK}")
find_package(amxb REQUIRED)
find_package(amxc REQUIRED)
find_package(amxd REQUIRED)
find_package(amxp REQUIRED)
find_package(amxo REQUIRED)
target_link_libraries(${PROJECT_NAME} amxb amxc amxd amxp amxo elpp )
target_link_libraries(${PROJECT_NAME} ${cli_libraries} tlvf)

target_include_directories(${PROJECT_NAME} 
    PRIVATE
        ${MODULE_PATH}/../bml
        ${MODULE_PATH}/../../../external
        $<TARGET_PROPERTY:bcl,INTERFACE_INCLUDE_DIRECTORIES>
        $<TARGET_PROPERTY:btlvf,INTERFACE_INCLUDE_DIRECTORIES>
)

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
