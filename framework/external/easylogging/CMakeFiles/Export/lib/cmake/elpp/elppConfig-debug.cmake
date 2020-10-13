#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "elpp" for configuration "Debug"
set_property(TARGET elpp APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(elpp PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libelpp.so.1.4.0"
  IMPORTED_SONAME_DEBUG "libelpp.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS elpp )
list(APPEND _IMPORT_CHECK_FILES_FOR_elpp "${_IMPORT_PREFIX}/lib/libelpp.so.1.4.0" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
