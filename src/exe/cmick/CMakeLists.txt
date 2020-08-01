cmake_minimum_required(VERSION 3.10)

project(cmick)

set (SOURCES
	main.cpp
)

add_executable (
	cmick
	${SOURCES}
)

target_link_libraries(cmick

	mceliece348864

	crypto
	keccak
	ssl
)


