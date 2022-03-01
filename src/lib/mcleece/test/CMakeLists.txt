cmake_minimum_required(VERSION 3.10)

project(mcleece_test)

set (SOURCES
	test.cpp
	actionsTest.cpp
	apiTest.cpp
	apiCliTest.cpp
	cboxTest.cpp
	messageTest.cpp
	private_keyTest.cpp
	simpleTest.cpp
)

include_directories(
	${libmcleece_proj_SOURCE_DIR}/test
	${libmcleece_proj_SOURCE_DIR}/test/lib
	${CMAKE_CURRENT_SOURCE_DIR}/..
)

add_executable (
	mcleece_test
	${SOURCES}
)

add_test(mcleece_test mcleece_test)

target_link_libraries(mcleece_test

	mcleece_static
	${CPPFILESYSTEM}
)

