cmake_minimum_required(VERSION 3.10)

project ( libmcleece_proj )
enable_testing()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${libmcleece_proj_SOURCE_DIR}/dist" CACHE PATH "..." FORCE)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
if("${CMAKE_BUILD_TYPE}" STREQUAL "")
	set(CMAKE_BUILD_TYPE "RelWithDebInfo")
	set(CMAKE_C_FLAGS "${CFLAGS} -Wall -std=c99 -Os")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g -O2 -fpic")
endif()

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
        set(CPPFILESYSTEM "stdc++fs")
    endif()
endif()

set (PROJECTS
	src/exe/cmc
	src/exe/mick

	src/lib/mcleece
	src/lib/serialize
	src/lib/util

	src/third_party_lib/base64
	src/third_party_lib/libkeccak
	src/third_party_lib/mceliece348864
	src/third_party_lib/mceliece8192128
)

include_directories(
	${libmcleece_proj_SOURCE_DIR}/src/lib/
	${libmcleece_proj_SOURCE_DIR}/src/third_party_lib/
)

foreach(proj ${PROJECTS})
	add_subdirectory(${proj} build/${proj})
endforeach()

