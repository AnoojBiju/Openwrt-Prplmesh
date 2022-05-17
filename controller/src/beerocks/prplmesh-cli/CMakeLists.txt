project(prplmesh_cli VERSION ${prplmesh_VERSION})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite} for the ${BoldGreen}${TARGET_PLATFORM}${BoldWhite} platform${ColourReset}")

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

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

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
