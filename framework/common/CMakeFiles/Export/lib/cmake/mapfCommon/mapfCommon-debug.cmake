#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "mapf::mapfcommon" for configuration "Debug"
set_property(TARGET mapf::mapfcommon APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(mapf::mapfcommon PROPERTIES
  IMPORTED_LINK_DEPENDENT_LIBRARIES_DEBUG "elpp"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libmapfcommon.so.1.4.0"
  IMPORTED_SONAME_DEBUG "libmapfcommon.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS mapf::mapfcommon )
list(APPEND _IMPORT_CHECK_FILES_FOR_mapf::mapfcommon "${_IMPORT_PREFIX}/lib/libmapfcommon.so.1.4.0" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
