cmake_minimum_required(VERSION 3.10)

project ( cmick_proj )
enable_testing()

set (PROJECTS
	src/exe/cmick
	src/lib/mceliece348864

	src/third_party_lib/libkeccak
)

include_directories(
	${cmick_proj_SOURCE_DIR}/src/lib/
	${cmick_proj_SOURCE_DIR}/src/third_party_lib/
)

foreach(proj ${PROJECTS})
	add_subdirectory(${proj} build/${proj})
endforeach()

