add_library(ieee1905_transport_lib 
    ieee1905_transport.cpp 
    ieee1905_transport_broker.cpp 
    ieee1905_transport_network.cpp 
    ieee1905_transport_local_bus.cpp 
    ieee1905_transport_packet_processing.cpp)

set_target_properties(ieee1905_transport_lib PROPERTIES VERSION ${prplmesh_VERSION} SOVERSION ${prplmesh_VERSION_MAJOR})
target_link_libraries(ieee1905_transport_lib 
    PUBLIC bpl bcl tlvf btlvf ieee1905_transport_messages mapfcommon
    PRIVATE elpp)
target_include_directories(ieee1905_transport_lib PUBLIC include/)

add_library(ieee1905_transport_messages ieee1905_transport_messages.cpp)
set_target_properties(ieee1905_transport_messages PROPERTIES VERSION ${prplmesh_VERSION} SOVERSION ${prplmesh_VERSION_MAJOR})
target_link_libraries(ieee1905_transport_messages PUBLIC mapfcommon bcl PRIVATE elpp)
target_include_directories(ieee1905_transport_messages PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )

add_executable(ieee1905_transport main.cpp)

if (TARGET_PLATFORM STREQUAL "rdkb")
    list(APPEND LINKED_LIBS breakpadwrapper)
endif()

target_link_libraries(ieee1905_transport PUBLIC ieee1905_transport_lib ${LINKED_LIBS} PRIVATE elpp)



install(TARGETS ieee1905_transport_messages ieee1905_transport_lib ieee1905_transport
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(test)
