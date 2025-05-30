# Determine the current vendor, export to CURRENT_VENDOR
if (NOT DEFINED CURRENT_VENDOR)
    execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/getinfo current
                    OUTPUT_VARIABLE CURRENT_VENDOR_OUT OUTPUT_STRIP_TRAILING_WHITESPACE
                    COMMAND_ERROR_IS_FATAL ANY)

    set(CURRENT_VENDOR "${CURRENT_VENDOR_OUT}" CACHE STRING "Select the system vendor")
    message(STATUS "Detected vendor: ${CURRENT_VENDOR_OUT}")
else()
    message(STATUS "Detected vendor: ${CURRENT_VENDOR} (cached)")
endif()

# Handle sources.list example
if (WITH_DOC OR WITH_DOC_EXAMPLES)
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${CURRENT_VENDOR}/${CURRENT_VENDOR}.sources.in")
    set(sources_in "${CURRENT_VENDOR}/${CURRENT_VENDOR}.sources.in")
    set(sources_out "${CURRENT_VENDOR}.sources")
else()
    set(sources_in "${CURRENT_VENDOR}/sources.list.in")
    set(sources_out "sources.list")
endif()
add_vendor_file(OUTPUT ${sources_out}
                INPUT "${sources_in}"
                MODE 644
                VARIABLES sourceslist-list-format
                          debian-stable-codename
                          debian-oldstable-codename
                          debian-testing-codename
                          ubuntu-codename
                          current-codename)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${sources_out}
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)
endif()

# Handle apt.conf snippets
file(GLOB conffiles ${CURRENT_VENDOR}/apt.conf-*)
foreach(file ${conffiles})
    file(RELATIVE_PATH confname ${CMAKE_CURRENT_SOURCE_DIR}/${CURRENT_VENDOR}/ ${file})
    string(REPLACE "apt.conf-" "" confname "${confname}")
    install(FILES "${file}"
            DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/apt/apt.conf.d/"
            RENAME "${confname}")
endforeach()

if (EXISTS "${CURRENT_VENDOR}/CMakeLists.txt")
    add_subdirectory(${CURRENT_VENDOR})
endif()
