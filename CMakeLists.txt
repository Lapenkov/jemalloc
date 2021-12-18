cmake_minimum_required(VERSION 3.20)

include(CheckCCompilerFlag)

project(jemalloc VERSION 5.3.0 LANGUAGES C CXX) # TODO: move version logic

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

function(je_cflag_add flag)
    string(SUBSTRING ${flag} 1 -1 FLAG_TRIMMED)
    check_c_compiler_flag(${flag} "${FLAG_TRIMMED}_SUPPORTED")
    if ("${${FLAG_TRIMMED}_SUPPORTED}")
        message("Detected that ${flag} is supported, adding...")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}" PARENT_SCOPE)
        message("CFLAGS after the addition: ${CMAKE_C_FLAGS}")
    else()
        message("Unsupported flag ${flag}, ignoring...")
    endif()
endfunction()

function(je_cxxflag_add flag)
    string(SUBSTRING ${flag} 1 -1 FLAG_TRIMMED)
    check_cxx_compiler_flag(${flag} "${FLAG_TRIMMED}_SUPPORTED")
    if ("${${FLAG_TRIMMED}_SUPPORTED}")
        message("Detected that ${flag} is supported, adding...")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        message("CXXFLAGS after the addition: ${CMAKE_CXX_FLAGS}")
    else()
        message("Unsupported flag ${flag}, ignoring...")
    endif()
endfunction()

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    MESSAGE("Using GCC")
    je_cflag_add(-Werror=unknown-warning-option)
    je_cflag_add(-Wall)
    je_cflag_add(-Wextra)
    je_cflag_add(-Wshorten-64-to-32)
    je_cflag_add(-Wsign-compare)
    je_cflag_add(-Wundef)
    je_cflag_add(-Wno-format-zero-length)
    je_cflag_add(-Wpointer-arith)
    # This warning triggers on the use of the universal zero initializer, which
    # is a very handy idiom for things like the tcache static initializer (which
    # has lots of nested structs).  See the discussion at.
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
    je_cflag_add(-Wno-missing-braces)
    # This one too.
    je_cflag_add(-Wno-missing-field-initializers)
    je_cflag_add(-Wno-missing-attributes)
    je_cflag_add(-pipe)
    je_cflag_add(-g3)

elseif (CMAKE_C_COMPILER_ID MATCHES "Clang")
    MESSAGE("Using CLANG")
elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    MESSAGE("Using MSVC")
    je_cflag_add(-nologo)
    je_cflag_add(-Zi)
    je_cflag_add(-MT)
    je_cflag_add(-W3)
    je_cflag_add(-FS)
    je_cxxflag_add(-I${CMAKE_PROJECT_DIR}/include/msvc_compat)
elseif (CMAKE_C_COMPILER_ID STREQUAL "Cray")
    MESSAGE("Using Cray")
    # dnl cray compiler 8.4 has an inlining bug
    # if test "x$je_cv_cray_84" = "xyes" ; then
    #   JE_CFLAGS_ADD([-hipa2])
    #   JE_CFLAGS_ADD([-hnognu])
    # fi
    # dnl ignore unreachable code warning
    # JE_CFLAGS_ADD([-hnomessage=128])
    # dnl ignore redefinition of "malloc", "free", etc warning
    # JE_CFLAGS_ADD([-hnomessage=1357])
endif()

set(je_sources
    src/arena.c
    src/background_thread.c
    src/base.c
    src/bin.c
    src/bin_info.c
    src/bitmap.c
    src/buf_writer.c
    src/cache_bin.c
    src/ckh.c
    src/counter.c
    src/ctl.c
    src/decay.c
    src/div.c
    src/ecache.c
    src/edata.c
    src/edata_cache.c
    src/ehooks.c
    src/emap.c
    src/eset.c
    src/exp_grow.c
    src/extent.c
    src/extent_dss.c
    src/extent_mmap.c
    src/fxp.c
    src/hook.c
    src/hpa.c
    src/hpa_hooks.c
    src/hpdata.c
    src/inspect.c
    src/jemalloc.c
    src/large.c
    src/log.c
    src/malloc_io.c
    src/mutex.c
    src/nstime.c
    src/pa.c
    src/pac.c
    src/pa_extra.c
    src/pages.c
    src/pai.c
    src/peak_event.c
    src/prof.c
    src/prof_data.c
    src/prof_log.c
    src/prof_recent.c
    src/prof_stats.c
    src/prof_sys.c
    src/psset.c
    src/rtree.c
    src/safety_check.c
    src/san_bump.c
    src/san.c
    src/sc.c
    src/sec.c
    src/stats.c
    src/sz.c
    src/tcache.c
    src/test_hooks.c
    src/thread_event.c
    src/ticker.c
    src/tsd.c
    src/witness.c
    src/zone.c)

add_library(jemalloc ${je_sources})

