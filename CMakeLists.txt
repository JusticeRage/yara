cmake_minimum_required (VERSION 3.12)
project (yara LANGUAGES C CXX)

include(GNUInstallDirs)
find_package (Threads)

add_library(yara SHARED yara_wrapper.cpp yara_errors.cpp ahocorasick.c arena.c atoms.c compiler.c exec.c exefiles.c filemap.c grammar.c hash.c hex_grammar.c hex_lexer.c lexer.c libyara.c mem.c modules.c object.c parser.c proc.c re.c re_grammar.c re_lexer.c rules.c scan.c sizedstr.c stream.c strutils.c endian.c bitmask.c scanner.c stopwatch.c stack.c base64.c threading.c notebook.c
                        proc/none.c  # Disable all memory scanning functions
	                    modules/manape.c)
target_link_libraries(yara manacommons ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES})

include_directories(${PROJECT_SOURCE_DIR}
					${PROJECT_SOURCE_DIR}/include)

add_definitions("-DUSE_NO_PROC")

if (WIN32)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
			set_target_properties(yara PROPERTIES COMPILE_DEFINITIONS "YARA_EXPORT")
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_definitions(-fPIC)
    endif()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
endif()

# make install command for linux machines:
if ("${CMAKE_SYSTEM}" MATCHES "Linux")
	# Copy binaries
	install(TARGETS yara
			RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
			LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
			ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
