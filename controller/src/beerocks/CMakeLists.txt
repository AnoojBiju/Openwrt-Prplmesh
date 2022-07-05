# Build Beerocks Modules
add_subdirectory("bml")
add_subdirectory("cli")
add_subdirectory("master")

if (ENABLE_NBAPI)
    add_subdirectory("prplmesh-cli")
endif()
