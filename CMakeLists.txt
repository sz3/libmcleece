cmake_minimum_required(VERSION 3.10)

project ( libmcleece_proj )
enable_testing()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${libmcleece_proj_SOURCE_DIR}/dist" CACHE PATH "..." FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
	set(CMAKE_BUILD_TYPE "RelWithDebInfo")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99 -Os")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-Wall -g -O2")
endif()

if(DEFINED BUILD_PORTABLE_LINUX)
	# statically link c++/gcc (not libc!!)
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -static-libstdc++ -static-libgcc")
endif()

if(DEFINED BUILD_LIBSODIUM)
	set(SODIUM_DISABLE_TESTS ON)
	add_subdirectory(libsodium)
	include_directories("${libmcleece_proj_SOURCE_DIR}/libsodium/libsodium/src/libsodium/include/")
endif()

if(NOT DEFINED CPPFILESYSTEM AND NOT APPLE)
    set(CPPFILESYSTEM "stdc++fs")
endif()

set (PROJECTS
	src/exe/mcleececli

	src/lib/mcleece
	src/lib/serialize
	src/lib/util

	src/third_party_lib/base64
	src/third_party_lib/getline
	src/third_party_lib/libkeccak
	src/third_party_lib/mceliece6960119f
)

include_directories(
	${libmcleece_proj_SOURCE_DIR}/src/lib/
	${libmcleece_proj_SOURCE_DIR}/src/third_party_lib/
)

foreach(proj ${PROJECTS})
	add_subdirectory(${proj} build/${proj})
endforeach()

