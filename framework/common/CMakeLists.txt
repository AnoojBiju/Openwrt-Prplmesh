# Logging
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/framework_logging.conf.in"
	"${CMAKE_CURRENT_BINARY_DIR}/framework_logging.conf"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/framework_logging.conf" DESTINATION config)
file(COPY "${CMAKE_CURRENT_BINARY_DIR}/framework_logging.conf" DESTINATION "${CMAKE_MULTIAP_OUTPUT_DIRECTORY}/config/")

# mapfcommon sources
set(sources logger.cpp encryption.cpp utils.cpp hmac_wrapper.cpp)

# We use OpenSSL >=3.0.0 for data encryption
find_package(OpenSSL 3.0 QUIET)
if(NOT OpenSSL_FOUND)
	find_package(OpenSSL 1.1 REQUIRED)
endif()

# Create a single common library
add_library(mapfcommon ${sources})
set_target_properties(mapfcommon PROPERTIES VERSION ${prplmesh_VERSION} SOVERSION ${prplmesh_VERSION_MAJOR})
target_link_libraries(mapfcommon
	PRIVATE 
		elpp
		json-c 
	PUBLIC
		${OPENSSL_LIBRARIES}
)
target_include_directories(mapfcommon
	PUBLIC 
		${PLATFORM_INCLUDE_DIR}
		${OPENSSL_INCLUDE_DIR}
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/mapf_config.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/include/mapf/common/config.h"
)

target_include_directories(mapfcommon
		PUBLIC
				$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
				$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		PRIVATE
				$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/>
		)

install(TARGETS mapfcommon EXPORT mapfCommon
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT mapfCommon NAMESPACE mapf:: DESTINATION lib/cmake/mapfCommon)
add_subdirectory(test)
