cmake_minimum_required(VERSION 3.10)

project(mick)

set (SOURCES
	mick.cpp
)

add_executable (
	mick
	${SOURCES}
)

target_link_libraries(mick

	mcleece_static
)

add_custom_command(
	TARGET mick POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:mick> mick.dbg
	COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:mick>
)

install(
	TARGETS mick
	DESTINATION bin
)

