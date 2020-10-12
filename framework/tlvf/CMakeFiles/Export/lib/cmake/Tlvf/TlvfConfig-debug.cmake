#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "tlvf" for configuration "Debug"
set_property(TARGET tlvf APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(tlvf PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libtlvf.so.1.4.0"
  IMPORTED_SONAME_DEBUG "libtlvf.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS tlvf )
list(APPEND _IMPORT_CHECK_FILES_FOR_tlvf "${_IMPORT_PREFIX}/lib/libtlvf.so.1.4.0" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
