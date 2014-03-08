cmake_minimum_required (VERSION 2.6)
project (yara)
find_package (Threads)

if (WIN32)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
endif()

add_library(yara ahocorasick.c compiler.c filemap.c hex_grammar.c libyara.c proc.c re_lexer.c arena.c exec.c grammar.c hex_lexer.c mem.c re.c rules.c atoms.c exefiles.c hash.c lexer.c parser.c re_grammar.c utils.c)
target_link_libraries (yara ${CMAKE_THREAD_LIBS_INIT})
