cmake_minimum_required(VERSION 3.10)

project ( libmcleese_proj )
enable_testing()

set (PROJECTS
	src/exe/cmc

	#src/lib/mcleese

	src/third_party_lib/libkeccak
	src/third_party_lib/mceliece348864
)

include_directories(
	${libmcleese_proj_SOURCE_DIR}/src/lib/
	${libmcleese_proj_SOURCE_DIR}/src/third_party_lib/
)

foreach(proj ${PROJECTS})
	add_subdirectory(${proj} build/${proj})
endforeach()

