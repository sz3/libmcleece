cmake_minimum_required(VERSION 3.10)

project ( libmcleece_proj )
enable_testing()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set (PROJECTS
	src/exe/cmc
	src/exe/mickly

	src/lib/mcleece

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

