cmake_minimum_required(VERSION 3.10)

project(serialize_test)

set (SOURCES
	test.cpp
	b64_instreamTest.cpp
	b64_outstreamTest.cpp
)

include_directories(
	${libmcleece_proj_SOURCE_DIR}/test
	${libmcleece_proj_SOURCE_DIR}/test/lib
	${CMAKE_CURRENT_SOURCE_DIR}/..
)

add_executable (
	serialize_test
	${SOURCES}
)

add_test(serialize_test serialize_test)

target_link_libraries(serialize_test

	${CPPFILESYSTEM}
)

