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

	mceliece8192128

	crypto
	keccak
	sodium
	ssl
)


