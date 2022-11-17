if (BUILD_TESTS)
    project(vbss_unit_tests VERSION ${vbss_VERSION})
    set(unit_tests_sources
            ${vbss_unit_tests}
            ${CMAKE_CURRENT_LIST_DIR}/vbss_tests
            ${CMAKE_CURRENT_LIST_DIR}/../vbss_core.cpp
            )

    add_executable(${PROJECT_NAME}
            ${unit_tests_sources}
            )
    if (COVERAGE)
        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "--coverage -fPIC -O0")
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "--coverage")
    endif()
    target_link_libraries(${PROJECT_NAME} gtest_main gmock)
    target_include_directories(${PROJECT_NAME}
            PRIVATE
            ${PLATFORM_INCLUDE_DIR}
            PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            )

    install(TARGETS ${PROJECT_NAME} DESTINATION tests)
    add_test(NAME ${PROJECT_NAME} COMMAND $<TARGET_FILE:${PROJECT_NAME}>)
endif()
