cmake_minimum_required(VERSION 3.10)

project(mickly)

set (SOURCES
	mickly.cpp
)

add_executable (
	mickly
	${SOURCES}
)

target_link_libraries(mickly

	mceliece348864

	crypto
	keccak
	sodium
	ssl
)


