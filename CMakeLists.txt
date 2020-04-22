cmake_minimum_required(VERSION 3.13)
if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

project(arp VERSION 1.0.0)

option(FEATURE_PACK "Compile with support for packing data" ON)
option(FEATURE_UNPACK "Compile with support for unpacking data" ON)
option(FEATURE_DEFLATE "Compile with support for DEFLATE compression" ON)
option(FEATURE_LZMA "Compile with support for LZMA compression" ON)
option(FEATURE_BZIP2 "Compile with support for bzip2 compression" ON)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(SEND_ERROR "In-source builds are not allowed.")
endif()

set(CMAKE_C_OUTPUT_EXTENSION_REPLACE 1)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# include dir for generated headers which must be copied (configs)
set(TMP_INCLUDE_DIR "${CMAKE_BINARY_DIR}/include.tmp")

set(EXT_LIBS "")

if(${FEATURE_DEFLATE})
  set(ZLIB_SOURCE_DIR "${CMAKE_SOURCE_DIR}/libs/zlib")
  configure_file("${ZLIB_SOURCE_DIR}/zconf.h.in" "${TMP_INCLUDE_DIR}/zlib/zconf.h")
  set(ZLIB_LIBRARY "zlib")
  set(ZLIB_INCLUDE_DIR "${ZLIB_SOURCE_DIR};${TMP_INCLUDE_DIR}/zlib")
  add_subdirectory("${ZLIB_SOURCE_DIR}")
  add_definitions("-DFEATURE_DEFLATE")
  list(APPEND EXT_LIBS "${ZLIB_LIBRARY}")
endif()
if(${FEATURE_LZMA})
  set(XZ_SOURCE_DIR "${CMAKE_SOURCE_DIR}/libs/xz")
  set(XZ_LIBRARY "liblzma")
  set(XZ_INCLUDE_DIR "${XZ_SOURCE_DIR}")
  set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
  add_subdirectory("${XZ_SOURCE_DIR}")
  add_definitions("-DFEATURE_LZMA")
  list(APPEND EXT_LIBS "${XZ_LIBRARY}")
endif()
if(${FEATURE_BZIP2})
  set(BZIP2_SOURCE_DIR "${CMAKE_SOURCE_DIR}/libs/bzip2")
  set(BZIP2_LIBRARY "bz2")
  set(BZIP2_INCLUDE_DIR "${BZIP2_SOURCE_DIR}")
  add_subdirectory("${BZIP2_SOURCE_DIR}")
  add_definitions("-DFEATURE_BZIP2")
  list(APPEND EXT_LIBS "${BZIP2_LIBRARY}")
endif()

set(SRC_DIR "src")
set(INC_DIR "include")

# source files
file(GLOB C_FILES ${SRC_DIR}/*.c)
file(GLOB H_FILES ${SRC_DIR}/*.h)

set(DIST_DIR "${CMAKE_BINARY_DIR}/dist")

set(LIB_OUT_DIR "${DIST_DIR}/lib")

set(LIBRARY_OUTPUT_PATH "${LIB_OUT_DIR}")

# configure the copy headers task
set(HDR_TARGET "${PROJECT_NAME}_headers")
set(HDR_OUT_DIR "${DIST_DIR}/include/")
add_custom_target(${HDR_TARGET})
add_custom_command(TARGET ${HDR_TARGET} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E
    make_directory ${HDR_OUT_DIR})
add_custom_command(TARGET ${HDR_TARGET} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E
    copy_directory "${CMAKE_SOURCE_DIR}/${INC_DIR}" "${HDR_OUT_DIR}")

add_library("${PROJECT_NAME}" SHARED ${C_FILES} ${H_FILES})

target_include_directories("${PROJECT_NAME}" PUBLIC "${CMAKE_SOURCE_DIR}/${INC_DIR}")

target_link_libraries("${PROJECT_NAME}" "${EXT_LIBS}")

# set the C standard
set_target_properties(${PROJECT_NAME} PROPERTIES C_STANDARD 11)
# enable PIC
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
# export all symbols (required on Windows)
set_target_properties(${PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

if(MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Od")
  if(MSVC_VERSION LESS 1911)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /DEBUG:FULL /Od")
  else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /DEBUG:FASTLINK /Od")
  endif()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2")
else()
  set(CMAKE_C_FLAGS "-Wall -Wextra -Winit-self -Wuninitialized \
                     -Wmissing-declarations -Winit-self -pedantic -pedantic-errors -std=c11")
  set(CMAKE_C_FLAGS_DEBUG "-g")
  set(CMAKE_C_FLAGS_RELEASE "-O3")
endif()

# make the copy headers target a dependency to force it to run
add_dependencies(${PROJECT_NAME} ${HDR_TARGET})

# copy dependency output
function(copy_dep_output DEP_TARGET)
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD 
    COMMAND "${CMAKE_COMMAND}" -E copy
      "$<TARGET_FILE:${DEP_TARGET}>"
      "${DIST_DIR}/lib/$<IF:$<BOOL:${MSVC}>,$<CONFIG>/,>$<TARGET_FILE_NAME:${DEP_TARGET}>"
    COMMENT "Copying '${DEP_TARGET}' dist output to output directory")
  if(WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy
        "$<TARGET_LINKER_FILE:${DEP_TARGET}>"
        "${DIST_DIR}/lib/$<IF:$<BOOL:${MSVC}>,$<CONFIG>/,>$<TARGET_LINKER_FILE_NAME:${DEP_TARGET}>"
      COMMENT "Copying '${DEP_TARGET}' linker output to output directory")
  endif()
endfunction()

if("${FEATURE_DEFLATE}")
  copy_dep_output("${ZLIB_LIBRARY}")
endif()
if("${FEATURE_LZMA}")
  copy_dep_output("${XZ_LIBRARY}")
endif()
if("${FEATURE_BZIP2}")
  copy_dep_output("${BZIP2_LIBRARY}")
endif()
