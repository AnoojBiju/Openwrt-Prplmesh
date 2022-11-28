configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/include/config.h"
)

include_directories("${CMAKE_CURRENT_BINARY_DIR}/include/")

# Build Beerocks Modules
add_subdirectory("bml")
add_subdirectory("cli")
add_subdirectory("master")

if (ENABLE_NBAPI)
    add_subdirectory("prplmesh-cli")
endif()
