cmake_minimum_required(VERSION 3.12)
if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

project(arp VERSION 1.0.0)

set(LIBARP_VERSION_SUFFIX "-dev")
set(LIBARP_VERSION "${CMAKE_PROJECT_VERSION}${LIBARP_VERSION_SUFFIX}" CACHE STRING "" FORCE)

set(LIBRARY_BASE_NAME arp)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

if(WIN32)
  set(CMAKE_SHARED_LIBRARY_PREFIX "")
  set(CMAKE_SHARED_MODULE_PREFIX "")
  set(CMAKE_IMPORT_LIBRARY_PREFIX "")
  set(CMAKE_STATIC_LIBRARY_PREFIX "")

  set(CMAKE_IMPORT_LIBRARY_SUFFIX ".dll.lib")
  set(CMAKE_STATIC_LIBRARY_SUFFIX ".lib")
endif()

set(LIBARP_USER_MAPPINGS "" CACHE STRING "Path to user-supplied media type mappings")

option(LIBARP_FEATURE_PACK "Compile with support for packing data" ON)
option(LIBARP_FEATURE_UNPACK "Compile with support for unpacking data" ON)
option(LIBARP_FEATURE_DEFLATE "Compile with support for DEFLATE compression" ON)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
if("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
  message(SEND_ERROR "In-source builds are not allowed.")
endif()

set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE 1)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(IS_TARGET_X86 0)
if(MSVC AND CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "AMD64")
  set(IS_TARGET_X86 1)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
  set(IS_TARGET_X86 1)
endif()

# include dir for generated headers which must be copied (configs)
set(TMP_INCLUDE_DIR "${PROJECT_BINARY_DIR}/include.tmp")

set(EXT_LIBS "")
set(EXT_LIBS_STATIC "")

if(${LIBARP_FEATURE_DEFLATE})
  set(ZLIB_SOURCE_DIR "${PROJECT_SOURCE_DIR}/libs/zlib")
  set(ZLIB_INCLUDE_DIR "${ZLIB_SOURCE_DIR};${TMP_INCLUDE_DIR}/zlib")
  add_definitions("-DFEATURE_DEFLATE")
  configure_file("${ZLIB_SOURCE_DIR}/zconf.h.in" "${TMP_INCLUDE_DIR}/zlib/zconf.h")
  set(ZLIB_LIBRARY "zlib")
  set(ZLIB_LIBRARY_STATIC "zlibstatic")
  list(APPEND EXT_LIBS "${ZLIB_LIBRARY}")
  list(APPEND EXT_LIBS_STATIC "${ZLIB_LIBRARY_STATIC}")

  if(NOT TARGET "zlib")
    set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory("${ZLIB_SOURCE_DIR}")
    set_target_properties(minigzip example
                            PROPERTIES EXCLUDE_FROM_ALL 1 EXCLUDE_FROM_DEFAULT_BUILD 1)
    if(TARGET minigzip64)
      set_target_properties(minigzip64 example64
                              PROPERTIES EXCLUDE_FROM_ALL 1 EXCLUDE_FROM_DEFAULT_BUILD 1)
    endif()
  endif()
endif()

if(WIN32)
  list(APPEND EXT_LIBS "shlwapi")
  list(APPEND EXT_LIBS_STATIC "shlwapi")
endif()

set(SRC_DIR "${PROJECT_SOURCE_DIR}/src")
set(PACK_SRC_DIR "${SRC_DIR}/pack")
set(UNPACK_SRC_DIR "${SRC_DIR}/unpack")
set(UTIL_SRC_DIR "${SRC_DIR}/util")

set(INC_DIR "${PROJECT_SOURCE_DIR}/include")
set(TOOLING_DIR "${PROJECT_SOURCE_DIR}/tooling")

set(TEMP_INC_DIR "${PROJECT_BINARY_DIR}/include.tmp")
set(TEMP_SRC_DIR "${PROJECT_BINARY_DIR}/src.tmp")

set(GENERATED_SRC_DIR "${TEMP_SRC_DIR}/internal/generated")
set(GENERATED_INC_DIR "${TEMP_INC_DIR}/internal/generated")

# generate resource sources
# first we generate a master media type map
message("Generating resource sources")
execute_process(COMMAND "ruby" "${TOOLING_DIR}/generate_mt_mappings.rb" "${LIBARP_USER_MAPPINGS}"
    WORKING_DIRECTORY "${TOOLING_DIR}"
    RESULT_VARIABLE CMD_RES)
if(CMD_RES)
  message(FATAL_ERROR "    generate_mt_mappings.rb: ${CMD_RES}")
endif()

# then we generate the actual source files
file(MAKE_DIRECTORY "${GENERATED_SRC_DIR}")
file(MAKE_DIRECTORY "${GENERATED_INC_DIR}")
execute_process(COMMAND "ruby" "${TOOLING_DIR}/abacus/abacus.rb"
      "${TOOLING_DIR}/output/media_types.csv"
      "-h ${GENERATED_INC_DIR}/"
      "-c ${GENERATED_SRC_DIR}/"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    RESULT_VARIABLE CMD_RES)
if(CMD_RES)
  message(FATAL_ERROR "    abacus.rb: ${CMD_RES}")
endif()

# source files
file(GLOB_RECURSE GENERATED_C_FILES ${GENERATED_SRC_DIR}/*.c)
list(APPEND C_FILES "${GENERATED_C_FILES}")
file(GLOB_RECURSE UTIL_C_FILES ${UTIL_SRC_DIR}/*.c)
list(APPEND C_FILES "${UTIL_C_FILES}")
if(${LIBARP_FEATURE_PACK})
  file(GLOB_RECURSE PACK_C_FILES ${PACK_SRC_DIR}/*.c)
  list(APPEND C_FILES "${PACK_C_FILES}")
  endif()
  if(${LIBARP_FEATURE_UNPACK})
  file(GLOB_RECURSE UNPACK_C_FILES ${UNPACK_SRC_DIR}/*.c)
  list(APPEND C_FILES "${UNPACK_C_FILES}")
endif()
file(GLOB_RECURSE H_FILES ${SRC_DIR}/*.h)

set(DIST_DIR "${PROJECT_BINARY_DIR}/dist")

set(LIB_OUT_DIR "${DIST_DIR}/lib")

set(LIBRARY_OUTPUT_PATH "${LIB_OUT_DIR}")

# configure the copy headers task
set(HDR_TARGET "${PROJECT_NAME}_headers")
set(HDR_OUT_DIR "${DIST_DIR}/include")
add_custom_target(${HDR_TARGET})
add_custom_command(TARGET ${HDR_TARGET} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E
    make_directory ${HDR_OUT_DIR})
add_custom_command(TARGET ${HDR_TARGET} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E
    copy_directory "${INC_DIR}/${PROJECT_NAME}/" "${HDR_OUT_DIR}/${PROJECT_NAME}/")

add_library("${PROJECT_NAME}" SHARED ${C_FILES} ${H_FILES})
add_library("${PROJECT_NAME}_static" STATIC ${C_FILES} ${H_FILES})

target_include_directories("${PROJECT_NAME}" PUBLIC "${INC_DIR};${TEMP_INC_DIR}")
target_include_directories("${PROJECT_NAME}_static" PUBLIC "${INC_DIR};${TEMP_INC_DIR}")

if(${LIBARP_FEATURE_DEFLATE})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${ZLIB_INCLUDE_DIR}")
  target_include_directories("${PROJECT_NAME}_static" PUBLIC "${ZLIB_INCLUDE_DIR}")
endif()

target_link_libraries("${PROJECT_NAME}" "${EXT_LIBS}")
target_link_libraries("${PROJECT_NAME}_static" "${EXT_LIBS_STATIC}")

# set the C standard
set_target_properties("${PROJECT_NAME}" PROPERTIES C_STANDARD 11)
set_target_properties("${PROJECT_NAME}" PROPERTIES C_STANDARD_REQUIRED ON)
set_target_properties("${PROJECT_NAME}" PROPERTIES C_EXTENSIONS OFF)
set_target_properties("${PROJECT_NAME}_static" PROPERTIES C_STANDARD 11)
set_target_properties("${PROJECT_NAME}_static" PROPERTIES C_STANDARD_REQUIRED ON)
set_target_properties("${PROJECT_NAME}_static" PROPERTIES C_EXTENSIONS OFF)
# enable PIC
set_target_properties("${PROJECT_NAME}" PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties("${PROJECT_NAME}_static" PROPERTIES POSITION_INDEPENDENT_CODE ON)
# export all symbols (required on Windows)
set_target_properties("${PROJECT_NAME}" PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
set_target_properties("${PROJECT_NAME}_static" PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
# set target name
set_target_properties("${PROJECT_NAME}" PROPERTIES OUTPUT_NAME ${LIBRARY_BASE_NAME})
set_target_properties("${PROJECT_NAME}_static" PROPERTIES OUTPUT_NAME ${LIBRARY_BASE_NAME})
# set shared library parameters
set_target_properties("${PROJECT_NAME}" PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties("${PROJECT_NAME}_static" PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties("${PROJECT_NAME}" PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

set_target_properties("${PROJECT_NAME}" PROPERTIES DEBUG_POSTFIX "d")
set_target_properties("${PROJECT_NAME}_static" PROPERTIES DEBUG_POSTFIX "d")

target_compile_definitions("${PROJECT_NAME}" PUBLIC "$<$<CONFIG:DEBUG>:LIBARP_DEBUG>")
target_compile_definitions("${PROJECT_NAME}_static" PUBLIC "$<$<CONFIG:DEBUG>:LIBARP_DEBUG>")

if(MSVC)
  add_compile_definitions("_CRT_SECURE_NO_WARNINGS" "_CRT_NONSTDC_NO_WARNINGS")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /wd4244 /wd4267")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Od")
  if(CMAKE_BUILD_TYPE MATCHES "Debug")
    if(MSVC_VERSION LESS 1911)
      set_property(TARGET "${PROJECT_NAME}" APPEND PROPERTY LINK_FLAGS /DEBUG)
      set_property(TARGET "${PROJECT_NAME}_static" APPEND PROPERTY LINK_FLAGS /DEBUG)
    else()
      set_property(TARGET "${PROJECT_NAME}" APPEND PROPERTY LINK_FLAGS /DEBUG)
      set_property(TARGET "${PROJECT_NAME}_static" APPEND PROPERTY LINK_FLAGS /DEBUG)
    endif()
  endif()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2")
else()
  add_compile_definitions("_POSIX_C_SOURCE=200809L" "_XOPEN_SOURCE=500")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -Winit-self -Wuninitialized -Wmissing-declarations \
                     -Wconversion -Wno-error=conversion -Wno-error=sign-conversion -pedantic -pedantic-errors")
  if(IS_TARGET_X86)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4.2")
  endif()
  if(MINGW)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
  endif()

  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")
endif()

# make the copy headers target a dependency to force it to run
add_dependencies("${PROJECT_NAME}" ${HDR_TARGET})
add_dependencies("${PROJECT_NAME}_static" ${HDR_TARGET})

# copy dependency output
function(copy_dep_output DEP_TARGET)
  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy
      "$<TARGET_FILE:${DEP_TARGET}>"
      "${DIST_DIR}/lib/$<IF:$<BOOL:${MSVC}>,$<CONFIG>/,>$<TARGET_FILE_NAME:${DEP_TARGET}>"
    COMMENT "Copying '${DEP_TARGET}' dist output to output directory")
  add_custom_command(TARGET "${PROJECT_NAME}_static" POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy
      "$<TARGET_FILE:${DEP_TARGET}>"
      "${DIST_DIR}/lib/$<IF:$<BOOL:${MSVC}>,$<CONFIG>/,>$<TARGET_FILE_NAME:${DEP_TARGET}>"
    COMMENT "Copying '${DEP_TARGET}' dist output to output directory")
  if(WIN32)
    add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy
        "$<TARGET_LINKER_FILE:${DEP_TARGET}>"
        "${DIST_DIR}/lib/$<IF:$<BOOL:${MSVC}>,$<CONFIG>/,>$<TARGET_LINKER_FILE_NAME:${DEP_TARGET}>"
      COMMENT "Copying '${DEP_TARGET}' linker output to output directory")
  endif()
endfunction()

if(${LIBARP_FEATURE_DEFLATE})
  copy_dep_output("${ZLIB_LIBRARY}")
endif()
