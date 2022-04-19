cmake_minimum_required(VERSION 3.10)

set (SOURCES
	mcleececli.cpp
)

add_executable (
	mcleececli
	${SOURCES}
)

target_link_libraries(mcleececli

	mcleece_static
)

add_custom_command(
	TARGET mcleececli POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:mcleececli> mcleececli.dbg
	COMMAND ${CMAKE_STRIP} $<TARGET_FILE:mcleececli>
)

install(
	TARGETS mcleececli
	DESTINATION bin
)

