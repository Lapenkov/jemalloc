cmake_minimum_required(VERSION 3.20)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckSourceCompiles)
include(CheckTypeSize)
include(TestBigEndian)

project(jemalloc VERSION 5.3.0 LANGUAGES C) # TODO: move version logic

set(CMAKE_C_STANDARD 99)

# --- Directories ---
set(JE_BUILD_UTIL_DIR "${CMAKE_SOURCE_DIR}/build_util")
# Directory where C programs are stored that test for available functionality and system features.
set(JE_C_TEST_DIR "${JE_BUILD_UTIL_DIR}/test")

# --- Revision ---
set(rev 2)

# --- Options ---
set(VERSION "detect" CACHE STRING "Number of significant virtual address bits")
option(ENABLE_CXX "Enable C++ support" ON)
set(LG_VADDR "detect" CACHE STRING "Number of significant virtual address bits")

# --- Functions ---
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

# Check if the code snippet compiles as a part of C program
function(je_code_compiles description main_body ret)
    message("Checking if ${description} compiles...")
    set(code
        "int main() { ${main_body} }")
    check_source_compiles(C "${code}" CODE_COMPILES)
    set(${ret} ${CODE_COMPILES} PARENT_SCOPE) 
    message("je_code_compiles result: ${CODE_COMPILES}")
endfunction()

function(je_code_compiles_header description header main_body ret)
    message("Checking if ${description} compiles...")
    set(code
        "${header}
        int main() { ${main_body} }")
    check_source_compiles(C "${code}" CODE_COMPILES)
    set(${ret} ${CODE_COMPILES} PARENT_SCOPE) 
    message("je_code_compiles result: ${CODE_COMPILES}")
endfunction()

if (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    MESSAGE("Using GCC or Clang")
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
elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    MESSAGE("Using MSVC")
    je_cflag_add(-nologo)
    je_cflag_add(-Zi)
    je_cflag_add(-MT)
    je_cflag_add(-W3)
    je_cflag_add(-FS)
    je_cxxflag_add(-I${CMAKE_PROJECT_DIR}/include/msvc_compat)

    check_include_file_cxx("inttypes.h" HAVE_INTTYPES_H)
    if (NOT HAVE_INTTYPES_H)
        je_cxxflag_add(-I${CMAKE_PROJECT_DIR}/include/msvc_compat/C99)
    endif()

else()
    message(FATAL_ERROR "Compiler ${CMAKE_C_COMPILER_ID} is unsupported")
endif()

# --- Built in type sizes ---
# TODO: figure what to do when compiler IS msvc -> configure.ac:350
if (NOT CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(LG_SIZEOF_PTR 3)
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(LG_SIZEOF_PTR 2)
    else()
        message(FATAL_ERROR "Unsupported pointer size: ${CMAKE_SIZEOF_VOID_P}")
    endif()
endif()

CHECK_TYPE_SIZE("int" INT_SIZE)
if (INT_SIZE EQUAL 8)
    set(LG_SIZEOF_INT 3)
elseif (INT_SIZE EQUAL 4)
    set(LG_SIZEOF_INT 2)
else()
    message(FATAL_ERROR "Unsupported int size: ${INT_SIZE}")
endif()
add_compile_definitions(LG_SIZEOF_INT=${LG_SIZEOF_INT})

CHECK_TYPE_SIZE("long" LONG_SIZE)
if (LONG_SIZE EQUAL 8)
    set(LG_SIZEOF_LONG 3)
elseif (LONG_SIZE EQUAL 4)
    set(LG_SIZEOF_LONG 2)
else()
    message(FATAL_ERROR "Unsupported long size: ${LONG_SIZE}")
endif()
add_compile_definitions(LG_SIZEOF_LONG=${LG_SIZEOF_LONG})

CHECK_TYPE_SIZE("long long" LONG_LONG_SIZE)
if (LONG_LONG_SIZE EQUAL 8)
    set(LG_SIZEOF_LONG_LONG 3)
elseif (LONG_LONG_SIZE EQUAL 4)
    set(LG_SIZEOF_LONG_LONG 2)
else()
    message(FATAL_ERROR "Unsupported long long size: ${LONG_LONG_SIZE}")
endif()
add_compile_definitions(LG_SIZEOF_LONG_LONG=${LG_SIZEOF_LONG_LONG})

CHECK_TYPE_SIZE("intmax_t" INTMAX_T_SIZE)
if (INTMAX_T_SIZE EQUAL 8)
    set(LG_SIZEOF_INTMAX_T 3)
elseif (INTMAX_T_SIZE EQUAL 4)
    set(LG_SIZEOF_INTMAX_T 2)
else()
    message(FATAL_ERROR "Unsupported intmax_t size: ${INTMAX_T_SIZE}")
endif()
add_compile_definitions(LG_SIZEOF_INTMAX_T=${LG_SIZEOF_INTMAX_T})

# --- CPU Specific settings ---
message ("Processor: ${CMAKE_SYSTEM_PROCESSOR}")
# TODO: Verify system processor is correctly detected
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    set(HAVE_CPU_SPINWAIT 1)
    if (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        je_code_compiles("Pause instruction MSVC" "_mm_pause(); return 0;" HAVE_PAUSE_MSVC)
        if (HAVE_PAUSE_MSVC)
            set(CPU_SPINWAIT "_mm_pause()")
        endif()
    else()
        je_code_compiles("Pause instruction" "__asm__ volatile(\"pause\"); return 0;" HAVE_ASM_PAUSE)
        if (HAVE_ASM_PAUSE)
            set(CPU_SPINWAIT "__asm__ volatile(\"pause\")")
        endif()
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(HAVE_CPU_SPINWAIT 1)
    je_code_compiles("Yield instruction" "__asm__ volatile(\"yield\"); return 0;" HAVE_ASM_YIELD)
    if (HAVE_ASM_YIELD)
        set(CPU_SPINWAIT "__asm__ volatile(\"yield\")")
    endif()
else()
    set(HAVE_CPU_SPINWAIT 0)
endif()

add_compile_definitions(HAVE_CPU_SPINWAIT=${HAVE_CPU_SPINWAIT})
add_compile_definitions(CPU_SPINWAIT=${CPU_SPINWAIT})

# --- Endianness ---
test_big_endian(IS_BIG_ENDIAN)
if (IS_BIG_ENDIAN)
    add_compile_definitions(JEMALLOC_BIG_ENDIAN)
endif()

# --- Number of significant VADDR bits ---
if (LG_VADDR STREQUAL "detect")
    message("Detecting the number of significant address bits")
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        if (LG_SIZEOF_PTR EQUAL 2)
            set(LG_VADDR 32)
        else()
            set(LG_VADDR 48)
        endif()
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        try_run(LG_VADDR_RUN_RESULT
            LG_VADDR_COMPILE_RESULT
            ${CMAKE_BINARY_DIR}
            ${JE_C_TEST_DIR}/lg_vaddr.c
            RUN_OUTPUT_VARIABLE LG_VADDR_RUN_OUTPUT)
        if (NOT (LG_VADDR_COMPILE_RESULT AND LG_VADDR_RUN_OUTPUT EQUAL 0))
            set(LG_VADDR ${LG_VADDR_RUN_OUTPUT})
        else()
            message(FATAL_ERROR "Cannot determine number of significant virtual address bits by running test program lg_vaddr.c")
        endif()
    else()
        # TODO: Finish other arch vaddr
        # configure.ac: 465
    endif()
endif()
add_compile_definitions(LG_VADDR=${LG_VADDR})

# --- Utility programs ---
find_program(AWK awk mawk gawk)
find_program(NM nm)
find_program(GIT git)

# --- Version ---
# TODO: Recreate version logic (or make it better)

# --- Platform ---
set(so "so")
set(importlib "${so}")
set(a "a")
set(libprefix "lib")
set(link_whole_archive "0")
set(DSO_LDFLAGS "-shared -Wl,-soname,$(@F)")
set(RPATH "-Wl,-rpath,$(1)")
set(SOREV "${so}.${rev}")
set(PIC_CFLAGS "-fPIC -DPIC")
set(CTARGET "-o $@")
set(LDTARGET "-o $@")
set(TEST_LD_MODE )
set(EXTRA_LDFLAGS )
set(ARFLAGS "crus")
set(AROUT " $@")
set(CC_MM TRUE)
if (APPLE)
    # TODO: is it needed at all? Looks like used in tests to modify PATH
    set(abi "macho")
    set(rpath "")
    set(LD_PRELOAD_VAR "DYLD_INSERT_LIBRARIES")
    set(so "dylib")
    set(importlib "${so}")
    set(force_tls FALSE)
    set(DSO_LDFLAGS "-shared -Wl,-install_name,$(LIBDIR)/$(@F)")
    set(SOREV "${rev}.${so}")
    set(sbrk_deprecated TRUE)
    set(SYM_PREFIX "_")
elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    set(abi "elf")
    je_cxxflag_add("-D_BSD_SOURCE")
    set(JEMALLOC_SYSCTL_VM_OVERCOMMIT FALSE)
    set(force_lazy_lock TRUE)
elseif (LINUX)
    set(abi "elf")
    je_cxxflag_add("-D_GNU_SOURCE")
    set(glibc TRUE)
    set(JEMALLOC_PURGE_MADVICE_DONTNEED_ZEROS FALSE)
	set(JEMALLOC_HAS_ALLOCA_H TRUE)
    set(JEMALLOC_PROC_SYS_VM_OVERCOMMIT_MEMORY FALSE)
    set(JEMALLOC_THREADED_INIT FALSE)
    set(JEMALLOC_USE_CXX_THROW FALSE)
    if (LG_SIZEOF_PTR EQUAL 3)
        set(default_retain TRUE)
    endif()
    # TODO: handle the rest of OSes -> configure.ac:650
endif()

# --- Usable size const ---
je_code_compiles_header("malloc_usable_size definition can use const argument"
    "
    #include <malloc.h>
    #include <stddef.h>
    size_t malloc_usable_size(const void *ptr);
    "
    ""
    USABLE_SIZE_CONST_COMPILES)
if (USABLE_SIZE_CONST_COMPILES)
    set(JEMALLOC_USABLE_SIZE_CONST "const")
endif()

# --- Log function ---
check_symbol_exists(log "math.h" LOG_FUNCTION_EXISTS)
if (NOT LOG_FUNCTION_EXISTS)
    unset(LOG_FUNCTION_EXISTS)
    set(CMAKE_REQUIRED_LIBRARIES "m")
    check_symbol_exists(log "math.h" LOG_FUNCTION_EXISTS)
    if (LOG_FUNCTION_EXISTS)
        set(LINK_AGAINST_LIBM TRUE CACHE BOOL "" FORCE)
    else()
        message(FATAL_ERROR "Failed to find log() function")
    endif()
endif()

# --- __attribute__ syntax ---
je_code_compiles_header("__attribute__ syntax"
    "static __attribute__((unused)) void foo(void){}"
    ""
    ATTRIBUTE_SYNTAX_COMPILES)
if (ATTRIBUTE_SYNTAX_COMPILES)
    set(JEMALLOC_HAVE_ATTR TRUE)
    if ((GCC OR CLANG) AND abi STREQUAL "elf")
        je_cflag_add(-fvisibility=hidden)
        je_cxxflag_add(-fvisibility=hidden)
    endif()
endif()

# TODO: continue @ configure.ac:849

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

if (ENABLE_CXX)
    enable_language(CXX)
    # Require at least C++14
    target_compile_features(jemalloc PUBLIC cxx_std_14)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    je_cxxflag_add(-Wall)
    je_cxxflag_add(-Wextra)
    je_cxxflag_add(-g3)

    add_compile_definitions(JEMALLOC_ENABLE_CXX)
endif()

if (LINK_AGAINST_LIBM)
    target_link_libraries(jemalloc m)
endif()

# CMAKE_BINARY_DIR is the folder from where the build is running.
# Configured files will be dumped in this folder
je_cflag_add(-I${CMAKE_BINARY_DIR}/include)

configure_file("include/jemalloc/internal/jemalloc_preamble.h.in" "include/jemalloc/internal/jemalloc_preamble.h" @ONLY)

